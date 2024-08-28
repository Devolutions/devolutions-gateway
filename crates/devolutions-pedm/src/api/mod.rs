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
use win_api_wrappers::raw::Win32::Security::Authorization::{SetSecurityInfo, SE_KERNEL_OBJECT};
use win_api_wrappers::raw::Win32::Security::{WinBuiltinUsersSid, ACE_FLAGS, DACL_SECURITY_INFORMATION, PSID};
use win_api_wrappers::security::acl::{Ace, AceType, Acl};
use win_api_wrappers::token::Token;
use win_api_wrappers::undoc::PIPE_ACCESS_FULL_CONTROL;
use win_api_wrappers::utils::Pipe;

use crate::error::{Error, ErrorResponse};
use crate::utils::AccountExt;

mod elevate_session;
mod elevate_temporary;
mod launch;
mod logs;
mod policy;
mod revoke;
mod status;

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
        let handle = Handle::new_borrowed(handle).expect("the handled held by NamedPipeServer is valid");
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
    let acc = token.sid_and_attributes()?.sid.account(None)?;

    request.extensions_mut().insert(NamedPipeConnectInfo {
        user: acc.to_user(),
        token,
        pipe_process_id: pipe.client_process_id()?,
    });

    Ok(next.run(request).await)
}

fn create_pipe(pipe_name: &'static str) -> Result<NamedPipeServer> {
    let pipe = ServerOptions::new().write_dac(true).create(pipe_name)?;

    let dacl = Acl::with_aces(vec![
        Ace {
            flags: ACE_FLAGS(0),
            access_mask: GENERIC_READ.0 | GENERIC_WRITE.0,
            data: AceType::AccessAllowed(Sid::from_well_known(WinBuiltinUsersSid, None)?),
        },
        Ace {
            flags: ACE_FLAGS(0),
            access_mask: PIPE_ACCESS_FULL_CONTROL,
            data: AceType::AccessAllowed(Token::current_process_token().sid_and_attributes()?.sid),
        },
    ])
    .to_raw()?;

    // SAFETY: `SetSecurityInfo` needs a handle and four potential inputs. Since `securityinfo` only
    // mentions `DACL_SECURITY_INFORMATION`, only the `pDacl` argument is used.
    // We assume the `.to_raw()` function generated a correct ACL.
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

pub(crate) fn api_router() -> ApiRouter {
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

    aide::r#gen::in_context(|ctx| {
        ctx.schema = schemars::r#gen::SchemaGenerator::new(schemars::r#gen::SchemaSettings::openapi3());
    });

    let _ = api_router().finish_api_with(&mut api, |doc| doc.default_response::<Json<ErrorResponse>>());

    api
}

pub(crate) async fn serve(pipe_name: &'static str) -> Result<()> {
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
