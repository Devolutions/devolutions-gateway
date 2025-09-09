#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use mcp_proxy::internal::{decode_content_texts, extract_sse_json_line, unwrap_json_rpc_inner_result};
use mcp_proxy::{Config, JsonRpcRequest, McpProxy};

use std::collections::HashMap;

fn get_string_path(json: &tinyjson::JsonValue, path: &[&str]) -> String {
    let mut current = json;
    for &segment in path {
        if let Some(obj) = current.get::<HashMap<String, tinyjson::JsonValue>>() {
            current = obj.get(segment).unwrap();
        } else if let Some(arr) = current.get::<Vec<tinyjson::JsonValue>>() {
            let index: usize = segment.parse().unwrap();
            current = &arr[index];
        }
    }
    current.get::<String>().unwrap().clone()
}

fn get_number_path(json: &tinyjson::JsonValue, path: &[&str]) -> f64 {
    let mut current = json;
    for &segment in path {
        if let Some(obj) = current.get::<HashMap<String, tinyjson::JsonValue>>() {
            current = obj.get(segment).unwrap();
        } else if let Some(arr) = current.get::<Vec<tinyjson::JsonValue>>() {
            let index: usize = segment.parse().unwrap();
            current = &arr[index];
        }
    }
    *current.get::<f64>().unwrap()
}

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
    let mut text_obj = HashMap::new();
    text_obj.insert(
        "text".to_string(),
        tinyjson::JsonValue::String("hello\\u0027world\\ncode:\\u003Ctag\\u003E".to_string()),
    );

    let mut content_obj = HashMap::new();
    content_obj.insert(
        "content".to_string(),
        tinyjson::JsonValue::Array(vec![tinyjson::JsonValue::Object(text_obj)]),
    );

    let mut result_obj = HashMap::new();
    result_obj.insert("result".to_string(), tinyjson::JsonValue::Object(content_obj));

    let mut v = tinyjson::JsonValue::Object(result_obj);
    decode_content_texts(&mut v);

    assert_eq!(
        get_string_path(&v, &["result", "content", "0", "text"]),
        "hello'world\ncode:<tag>"
    );
}

#[test]
fn unwrap_json_rpc_inner_result_prefers_result() {
    let mut tools_obj = HashMap::new();
    tools_obj.insert("tools".to_string(), tinyjson::JsonValue::Array(vec![]));

    let mut v_obj = HashMap::new();
    v_obj.insert("result".to_string(), tinyjson::JsonValue::Object(tools_obj.clone()));

    let v = tinyjson::JsonValue::Object(v_obj);
    let got = unwrap_json_rpc_inner_result(v);

    let expected = tinyjson::JsonValue::Object(tools_obj);
    assert_eq!(got.stringify().unwrap(), expected.stringify().unwrap());
}

#[test]
fn unwrap_json_rpc_inner_result_passthrough() {
    let mut v_obj = HashMap::new();
    v_obj.insert("tools".to_string(), tinyjson::JsonValue::Array(vec![]));

    let v = tinyjson::JsonValue::Object(v_obj);
    let got = unwrap_json_rpc_inner_result(v.clone());
    assert_eq!(got.stringify().unwrap(), v.stringify().unwrap());
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
        get_string_path(resp.result.as_ref().unwrap(), &["protocolVersion"]),
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
    assert_eq!(get_number_path(resp.error.as_ref().unwrap(), &["code"]), -32601.0);
}
