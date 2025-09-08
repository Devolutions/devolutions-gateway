#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use mcp_proxy::private::{decode_content_texts, extract_sse_json_line, unwrap_json_rpc_inner_result};
use mcp_proxy::{Config, JsonRpcRequest, McpProxy};

use serde_json::json;

#[test]
fn sse_extracts_first_data_line() {
    let body = "event: message\ndata: {\"result\":{\"ok\":true}}\ndata: {\"result\":{\"ok\":false}}\n";
    let got = extract_sse_json_line(body);
    assert_eq!(got, Some("{\"result\":{\"ok\":true}}"));
}

#[test]
fn sse_no_data_is_none() {
    let body = "event: message\nretry: 1000\n\n";
    let got = extract_sse_json_line(body);
    assert_eq!(got, None);
}

#[test]
fn decode_escaped_texts_works() {
    let mut v = json!({
        "result": { "content": [
            { "text": "hello\\u0027world\\ncode:\\u003Ctag\\u003E" }
        ]}
    });
    decode_content_texts(&mut v);
    assert_eq!(
        v["result"]["content"][0]["text"].as_str().unwrap(),
        "hello'world\ncode:<tag>"
    );
}

#[test]
fn unwrap_json_rpc_inner_result_prefers_result() {
    let v = json!({"result": {"tools": []}});
    let got = unwrap_json_rpc_inner_result(v);
    assert_eq!(got, json!({"tools": []}));
}

#[test]
fn unwrap_json_rpc_inner_result_passthrough() {
    let v = json!({"tools": []});
    let got = unwrap_json_rpc_inner_result(v.clone());
    assert_eq!(got, v);
}

#[tokio::test]
async fn initialize_shape_is_stable() {
    let mut p = McpProxy::init(Config::http("http://unused".to_owned(), None))
        .await
        .unwrap();
    let resp = p
        .handle_jsonrpc_request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(1),
            method: "initialize".into(),
            params: None,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.jsonrpc, "2.0");
    assert!(resp.error.is_none());
    assert_eq!(
        resp.result.as_ref().unwrap()["protocolVersion"].as_str().unwrap(),
        "2024-11-05"
    );
}

#[tokio::test]
async fn unknown_method_is_32601() {
    let mut p = McpProxy::init(Config::http("http://unused".to_owned(), None))
        .await
        .unwrap();
    let resp = p
        .handle_jsonrpc_request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(7),
            method: "no-such".into(),
            params: None,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.error.as_ref().unwrap()["code"], -32601);
}
