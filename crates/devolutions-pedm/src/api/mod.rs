use core::{fmt, task};
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::time::Duration;

use aide::axum::ApiRouter;
use aide::openapi::{Info, OpenApi};
use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::{Json, Router};
use futures_util::future::BoxFuture;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tower::Layer;
use tower_http::timeout::TimeoutLayer;
use tower_service::Service;
use tracing::{error, info};

use devolutions_gateway_task::ShutdownSignal;
use devolutions_pedm_shared::policy::User;
use win_api_wrappers::handle::Handle;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::raw::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE};
use win_api_wrappers::raw::Win32::Security::Authorization::{GRANT_ACCESS, SE_KERNEL_OBJECT, SetSecurityInfo};
use win_api_wrappers::raw::Win32::Security::{DACL_SECURITY_INFORMATION, NO_INHERITANCE, WinBuiltinUsersSid};
use win_api_wrappers::security::acl::{Acl, ExplicitAccess, Trustee};
use win_api_wrappers::token::Token;
use win_api_wrappers::undoc::PIPE_ACCESS_FULL_CONTROL;
use win_api_wrappers::utils::Pipe;

use crate::config::Config;
use crate::db::{Db, DbAsyncBridgeTask, DbError, InitSchemaError};
use crate::error::{Error, ErrorResponse};
use crate::utils::AccountExt;

mod about;
mod elevate_session;
mod elevate_temporary;
mod err;
mod launch;
mod log;
mod policy;
mod revoke;
pub(crate) mod state;
mod status;

use self::about::about;
use self::launch::post_launch;
use self::state::{AppState, AppStateError};

#[derive(Debug, Clone)]
struct NamedPipeConnectInfo {
    pub(crate) user: User,
    pub(crate) token: Arc<Token>,
    pub(crate) pipe_process_id: u32,
}

#[derive(Debug, Clone)]
struct RawNamedPipeConnectInfo {
    pub(crate) handle: Handle,
}

impl Connected<&NamedPipeServer> for RawNamedPipeConnectInfo {
    fn connect_info(target: &NamedPipeServer) -> Self {
        let handle = HANDLE(target.as_raw_handle().cast());
        let handle = Handle::new_borrowed(handle).expect("the handle held by NamedPipeServer is valid");
        Self { handle }
    }
}

async fn named_pipe_middleware(
    ConnectInfo(info): ConnectInfo<RawNamedPipeConnectInfo>,
    mut request: Request,
    next: Next,
) -> Result<Response, Error> {
    let pipe = Pipe {
        handle: info.handle.try_clone()?,
    };

    let token = Arc::new(pipe.client_primary_token()?);
    let acc = token.sid_and_attributes()?.sid.lookup_account(None)?;

    request.extensions_mut().insert(NamedPipeConnectInfo {
        user: acc.to_user(),
        token,
        pipe_process_id: pipe.client_process_id()?,
    });

    Ok(next.run(request).await)
}

fn create_pipe(pipe_name: &str) -> anyhow::Result<NamedPipeServer> {
    let pipe = ServerOptions::new().write_dac(true).create(pipe_name)?;

    let dacl = Acl::new()?.set_entries(&[
        ExplicitAccess {
            access_permissions: GENERIC_READ.0 | GENERIC_WRITE.0,
            access_mode: GRANT_ACCESS,
            inheritance: NO_INHERITANCE,
            trustee: Trustee::Sid(Sid::from_well_known(WinBuiltinUsersSid, None)?),
        },
        ExplicitAccess {
            access_permissions: PIPE_ACCESS_FULL_CONTROL,
            access_mode: GRANT_ACCESS,
            inheritance: NO_INHERITANCE,
            trustee: Trustee::Sid(Token::current_process_token().sid_and_attributes()?.sid),
        },
    ])?;

    // SAFETY: `SetSecurityInfo` needs a handle and four potential inputs. Since `securityinfo` only
    // mentions `DACL_SECURITY_INFORMATION`, only the `pDacl` argument is used.
    unsafe {
        SetSecurityInfo(
            HANDLE(pipe.as_raw_handle().cast()),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl.as_ptr().cast()),
            None,
        )
        .ok()?;
    }

    Ok(pipe)
}

pub(crate) fn api_router() -> ApiRouter<AppState> {
    ApiRouter::new()
        .api_route("/about", aide::axum::routing::get(about))
        .api_route("/launch", aide::axum::routing::post(post_launch))
        .nest("/log", log::log_router())
        .nest("/policy", policy::policy_router())
        .layer(middleware::from_fn(named_pipe_middleware))
        .layer(TimeoutLayer::new(Duration::from_secs(5)))
}

pub fn openapi() -> OpenApi {
    let mut api = OpenApi {
        info: Info {
            title: "Devolutions PEDM API".to_owned(),
            ..Info::default()
        },
        ..OpenApi::default()
    };

    aide::generate::in_context(|ctx| {
        ctx.schema = schemars::r#gen::SchemaGenerator::new(schemars::r#gen::SchemaSettings::openapi3());
    });

    let _ = api_router().finish_api_with(&mut api, |doc| doc.default_response::<Json<ErrorResponse>>());

    api
}

/// A handler that is not part of the public API.
async fn health_check() -> &'static str {
    "OK"
}

/// Initializes the appliation and starts the named pipe server.
pub async fn serve(config: Config, shutdown_signal: ShutdownSignal) -> Result<(), ServeError> {
    let db = Db::new(&config).await?;
    db.setup().await?;

    let (db_handle, db_async_bridge_task) = DbAsyncBridgeTask::new(db.clone());
    let _db_async_bridge_task = devolutions_gateway_task::spawn_task(db_async_bridge_task, shutdown_signal);

    let state = AppState::new(db, db_handle, &config.pipe_name).await?;

    // a plain Axum router
    let hello_router = Router::new().route("/health", axum::routing::get(health_check));

    let app = api_router()
        .merge(ApiRouter::from(hello_router))
        .layer(LogLayer::new(state.clone())) // apply to the merged router
        .with_state(state.clone());

    let mut make_service = app.into_make_service_with_connect_info::<RawNamedPipeConnectInfo>();

    let pipe_name = &config.pipe_name;
    let mut server = create_pipe(pipe_name)?;

    // Log the server startup.
    info!("Started named pipe server with name `{pipe_name}`");
    info!(
        "Run ID is {run_id}, request ID counter is {req_count}",
        run_id = state.startup_info.run_id,
        req_count = state.req_counter.load(Ordering::Relaxed)
    );

    loop {
        server.connect().await?;
        let client = server;

        server = create_pipe(pipe_name)?;

        let Ok(tower_service) = make_service.call(&client).await;
        tokio::spawn(async move {
            let socket = TokioIo::new(client);

            let hyper_service = hyper::service::service_fn(move |req| tower_service.clone().call(req));

            if let Err(error) = server::conn::auto::Builder::new(TokioExecutor::new())
                .http1_only()
                .http1()
                .keep_alive(false)
                .serve_connection(socket, hyper_service)
                .await
            {
                error!(%error, "Failed to serve connection");
            }
        });
    }
}

#[derive(Debug)]
pub enum ServeError {
    TokioIo(tokio::io::Error),
    AppState(AppStateError),
    Db(DbError),
    InitSchema(InitSchemaError),
    Other(anyhow::Error),
}

impl core::error::Error for ServeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TokioIo(e) => Some(e),
            Self::AppState(e) => Some(e),
            Self::Db(e) => Some(e),
            Self::InitSchema(e) => Some(e),
            Self::Other(e) => Some(e.as_ref()),
        }
    }
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokioIo(e) => e.fmt(f),
            Self::AppState(e) => e.fmt(f),
            Self::Db(e) => e.fmt(f),
            Self::InitSchema(e) => e.fmt(f),
            Self::Other(e) => e.fmt(f),
        }
    }
}

impl From<tokio::io::Error> for ServeError {
    fn from(e: tokio::io::Error) -> Self {
        Self::TokioIo(e)
    }
}
impl From<AppStateError> for ServeError {
    fn from(e: AppStateError) -> Self {
        Self::AppState(e)
    }
}
impl From<DbError> for ServeError {
    fn from(e: DbError) -> Self {
        Self::Db(e)
    }
}
impl From<InitSchemaError> for ServeError {
    fn from(e: InitSchemaError) -> Self {
        Self::InitSchema(e)
    }
}
impl From<anyhow::Error> for ServeError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

/// A layer that logs HTTP requests and responses to the database.
#[derive(Clone)]
struct LogLayer {
    state: AppState,
}

impl LogLayer {
    pub(crate) fn new(state: AppState) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for LogLayer {
    type Service = LogService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LogService {
            inner,
            state: self.state.clone(),
        }
    }
}

#[derive(Clone)]
struct LogService<S> {
    inner: S,
    state: AppState,
}

impl<S> Service<Request> for LogService<S>
where
    S: Service<Request, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let req_id = self.state.req_counter.fetch_add(1, Ordering::Relaxed) + 1;

        // Make the request ID available to handlers.
        req.extensions_mut().insert(req_id);

        let db = Arc::clone(&self.state.db);
        let method = req.method().clone();
        let path = req.uri().path().to_owned();

        let fut = self.inner.call(req);

        Box::pin(async move {
            let resp: Response = fut.await?;
            let status_code = resp.status();
            info!("request ID: {req_id}, status code: {status_code}");
            tokio::spawn(async move {
                #[expect(clippy::cast_possible_wrap)]
                if let Err(error) = db
                    .log_http_request(req_id, method.as_str(), &path, status_code.as_u16() as i16)
                    .await
                {
                    error!(%error, "Failed to log HTTP request");
                }
                Ok::<_, DbError>(())
            });
            Ok(resp)
        })
    }
}
