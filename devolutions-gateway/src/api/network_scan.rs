use axum::{
    extract::{ws::Message, State, WebSocketUpgrade}, response::Response, routing::get, Router
};

use crate::{http::HttpError, DgwState};



pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/broadcast", get(broadcast))
        .with_state(state)
}

#[derive(Debug, Clone, serde::Deserialize)]
struct NetworkScanQueryParams{
    pub data: String
}

async fn broadcast(
    _: State<DgwState>,
    ws: WebSocketUpgrade,
    query_params: axum::extract::Query<NetworkScanQueryParams>,
) -> Result<Response, HttpError> {
    tracing::info!("We got here");
    let res = ws.on_upgrade(|mut websocket| async move {
        let data = query_params.data.clone();
        let send_back = format!("Hello World!: data {}", data);
        websocket.send(Message::Text(send_back)).await.unwrap();
    });

    Ok(res)
}
