use rocket_api_base::{BaseContent, BaseResponse, NoContent};
use serde::Serialize;
use serde_json::{json, Value};

use std::fs::File;
use std::io::Read;

const SERIALIZE_FILE: &'static str = "tests/base_response_serialize.json";
const SERIALIZE_NO_CONTENT_FILE: &'static str = "tests/base_response_serialize_no_content.json";

#[derive(Serialize)]
struct Person {
    age: u32,
    name: String,
    married: bool,
}

fn file_to_value(file_name: &'static str) -> Value {
    let mut file = File::open(file_name).unwrap();
    let mut expected_string = String::new();
    file.read_to_string(&mut expected_string).unwrap();
    serde_json::from_str(&expected_string).unwrap()
}

#[test]
fn basic_response_serialize() {
    let expected = file_to_value(SERIALIZE_FILE);
    let serialized = json!(BaseResponse {
        result: "ok".into(),
        error_code: 0,
        error_message: "".into(),
        content: BaseContent::Some(vec![Person {
            age: 19,
            name: "Pau".into(),
            married: false
        }]),
    });
    assert_eq!(expected, serialized);
}

#[test]
fn basic_response_serialize_no_content() {
    let expected = file_to_value(SERIALIZE_NO_CONTENT_FILE);
    let serialized = json!(BaseResponse::<NoContent> {
        result: "ok".into(),
        error_code: 0,
        error_message: "".into(),
        content: BaseContent::None,
    });
    assert_eq!(expected, serialized);
}
