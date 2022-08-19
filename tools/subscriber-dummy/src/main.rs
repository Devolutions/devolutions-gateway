use axum::body::Body;
use axum::http::Request;
use axum::routing::post;
use axum::Router;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/subscriber", post(post_message));
    let socket_addr = "0.0.0.0:9999".parse().unwrap();

    axum::Server::bind(&socket_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn post_message(req: Request<Body>) {
    println!("Request: {req:?}");
    let body = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let body = String::from_utf8_lossy(&body);
    println!("Body: {body}");
}
