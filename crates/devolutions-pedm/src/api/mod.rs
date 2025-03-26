use std::fmt::Debug;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use std::time::Duration;

use aide::axum::routing::{get, post};
use aide::axum::ApiRouter;
use aide::openapi::{Info, OpenApi};
use anyhow::Result;
use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Json;
use devolutions_pedm_shared::policy::User;
use elevate_session::post_elevate_session;
use elevate_temporary::post_elevate_temporary;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server;
use launch::post_launch;
use logs::get_logs;
use revoke::post_revoke;
use status::get_status;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tower_http::timeout::TimeoutLayer;
use tower_service::Service;
use tracing::error;
use win_api_wrappers::handle::Handle;
use win_api_wrappers::identity::sid::Sid;
use win_api_wrappers::raw::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE};
use win_api_wrappers::raw::Win32::Security::Authorization::{SetSecurityInfo, GRANT_ACCESS, SE_KERNEL_OBJECT};
use win_api_wrappers::raw::Win32::Security::{WinBuiltinUsersSid, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSID};
use win_api_wrappers::security::acl::{Acl, ExplicitAccess, Trustee};
use win_api_wrappers::token::Token;
use win_api_wrappers::undoc::PIPE_ACCESS_FULL_CONTROL;
use win_api_wrappers::utils::Pipe;

use crate::error::{Error, ErrorResponse};
use crate::utils::AccountExt;

pub mod elevate_session;
pub mod elevate_temporary;
pub mod launch;
pub mod logs;
pub mod policy;
pub mod revoke;
pub mod status;

#[derive(Debug, Clone)]
pub struct NamedPipeConnectInfo {
    pub user: User,
    pub token: Arc<Token>,
    pub pipe_process_id: u32,
}

#[derive(Debug, Clone)]
struct RawNamedPipeConnectInfo {
    pub handle: Handle,
}

impl Connected<&NamedPipeServer> for RawNamedPipeConnectInfo {
    fn connect_info(target: &NamedPipeServer) -> Self {
        let handle = HANDLE(target.as_raw_handle().cast());
        let handle = Handle::new_borrowed(handle).expect("the handle held by NamedPipeServer is valid");
        Self { handle }
    }
}

async fn named_pipe_middleware(
    ConnectInfo(raw_named_pipe_info): ConnectInfo<RawNamedPipeConnectInfo>,
    mut request: Request,
    next: Next,
) -> Result<Response, Error> {
    let pipe = Pipe {
        handle: raw_named_pipe_info.handle.try_clone()?,
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

fn create_pipe(pipe_name: &'static str) -> Result<NamedPipeServer> {
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
            PSID::default(),
            PSID::default(),
            Some(dacl.as_ptr().cast()),
            None,
        )
        .ok()?;
    }

    Ok(pipe)
}

pub fn api_router() -> ApiRouter {
    ApiRouter::new()
        .api_route("/elevate/temporary", post(post_elevate_temporary))
        .api_route("/elevate/session", post(post_elevate_session))
        .api_route("/launch", post(post_launch))
        .api_route("/revoke", post(post_revoke))
        .api_route("/logs", get(get_logs))
        .api_route("/status", get(get_status))
        .nest("/policy", policy::policy_router())
        .layer(middleware::from_fn(named_pipe_middleware))
        .layer(TimeoutLayer::new(Duration::from_secs(5)))
}

pub fn openapi() -> OpenApi {
    let mut api = OpenApi {
        info: Info {
            title: "Devolutions PEDM API".to_string(),
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

pub async fn serve(pipe_name: &'static str) -> Result<()> {
    let app = api_router();

    let mut make_service = app.into_make_service_with_connect_info::<RawNamedPipeConnectInfo>();

    let mut server = create_pipe(pipe_name)?;
    loop {
        server.connect().await?;
        let client = server;

        server = create_pipe(pipe_name)?;

        let tower_service = make_service.call(&client).await?;
        tokio::spawn(async move {
            let socket = TokioIo::new(client);

            let hyper_service =
                hyper::service::service_fn(move |request: Request<Incoming>| tower_service.clone().call(request));

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
