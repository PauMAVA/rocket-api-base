#![feature(proc_macro_hygiene, decl_macro)]

use rocket::http::uri::Uri;
use rocket::http::{Header, RawStr};
use rocket::local::{Client, LocalResponse};
use rocket::{get, routes, Rocket};
use rocket_api_base::{AuthError, BaseContent, BaseResponse, NoContent, RocketBasicAuthFairing};
use rocket_contrib::json::Json;
use serde_json::Value;
use std::fs::File;
use std::io::Read;

const MISSING_HEADER_FILE: &str = "tests/jwt_auth_handler_missing_header.json";
const INVALID_HEADER_FILE: &str = "tests/jwt_auth_handler_invalid_header.json";
const INVALID_FORMAT_FILE: &str = "tests/basic_auth_handler_invalid_format.json";
const INVALID_CREDENTIALS_FILE: &str = "tests/basic_auth_handler_invalid_credentials.json";
const OK_FILE: &str = "tests/jwt_auth_handler_ok.json";

fn file_to_value(file_name: &'static str) -> Value {
    let mut file = File::open(file_name).unwrap();
    let mut expected_string = String::new();
    file.read_to_string(&mut expected_string).unwrap();
    serde_json::from_str(&expected_string).unwrap()
}

fn response_to_value(mut res: LocalResponse) -> Value {
    serde_json::from_str(&res.body_string().unwrap()).unwrap()
}

#[get("/test")]
fn test_endpoint() -> Json<BaseResponse<NoContent>> {
    Json(BaseResponse::<NoContent> {
        result: "ok".to_string(),
        error_message: "".to_string(),
        error_code: 0,
        content: BaseContent::None,
    })
}

#[get("/test2")]
fn test2_endpoint() -> Json<BaseResponse<NoContent>> {
    Json(BaseResponse::<NoContent> {
        result: "ok".to_string(),
        error_message: "".to_string(),
        error_code: 0,
        content: BaseContent::None,
    })
}

#[get("/other")]
fn other_endpoint() -> Json<BaseResponse<NoContent>> {
    Json(BaseResponse::<NoContent> {
        result: "ok".to_string(),
        error_message: "".to_string(),
        error_code: 0,
        content: BaseContent::None,
    })
}

#[get("/auth_error?<message>")]
fn auth_error_endpoint(message: &RawStr) -> Json<BaseResponse<NoContent>> {
    Json(BaseResponse::<NoContent> {
        result: "error".to_string(),
        error_message: Uri::percent_decode_lossy(message.as_ref()).to_string(),
        error_code: 403,
        content: BaseContent::None,
    })
}

fn auth_error_handler(error: AuthError) -> String {
    "/auth_error?message=".to_string() + &error.get_message_encoded()
}

const USER: &str = "user";
const PASSWORD: &str = "password";

fn basic_auth_callback(user: String, password: String) -> Result<(), String> {
    if user.eq(USER) && password.eq(PASSWORD) {
        Ok(())
    } else {
        Err("/auth_error?message=".to_string() + &Uri::percent_encode("Invalid credentials"))
    }
}

fn start_test_server() -> Rocket {
    rocket::ignite()
        .attach(RocketBasicAuthFairing::new(
            basic_auth_callback,
            auth_error_handler,
        ))
        .mount(
            "/",
            routes![
                test_endpoint,
                test2_endpoint,
                other_endpoint,
                auth_error_endpoint
            ],
        )
}

fn start_test_server_with_excludes(excludes: Vec<&str>) -> Rocket {
    rocket::ignite()
        .attach(RocketBasicAuthFairing::new_with_excludes(
            basic_auth_callback,
            auth_error_handler,
            excludes,
        ))
        .mount(
            "/",
            routes![
                test_endpoint,
                test2_endpoint,
                other_endpoint,
                auth_error_endpoint
            ],
        )
}

fn start_test_server_with_includes(includes: Vec<&str>) -> Rocket {
    rocket::ignite()
        .attach(RocketBasicAuthFairing::new_with_includes(
            basic_auth_callback,
            auth_error_handler,
            includes,
        ))
        .mount(
            "/",
            routes![
                test_endpoint,
                test2_endpoint,
                other_endpoint,
                auth_error_endpoint
            ],
        )
}

#[test]
fn test_no_header() {
    let rocket = start_test_server();
    let client = Client::new(rocket).expect("valid rocket instance");
    let req = client.get("/test");
    let response = req.dispatch();
    assert_eq!(
        file_to_value(MISSING_HEADER_FILE),
        response_to_value(response)
    );
}

#[test]
fn test_invalid_header() {
    let rocket = start_test_server();
    let client = Client::new(rocket).expect("valid rocket instance");
    let mut req = client.get("/test");
    req.add_header(Header::new("Authorization", "Bearer bad_scheme"));
    let response = req.dispatch();
    assert_eq!(
        file_to_value(INVALID_HEADER_FILE),
        response_to_value(response)
    );
}

#[test]
fn test_invalid_format() {
    let rocket = start_test_server();
    let credentials = base64::encode(format!("{}-{}", USER, PASSWORD));
    let client = Client::new(rocket).expect("valid rocket instance");
    let mut req = client.get("/test");
    req.add_header(Header::new(
        "Authorization",
        format!("Basic {}", credentials),
    ));
    let response = req.dispatch();
    assert_eq!(
        file_to_value(INVALID_FORMAT_FILE),
        response_to_value(response)
    );
}

#[test]
fn test_invalid_credentials() {
    let rocket = start_test_server();
    let credentials = base64::encode("user:bad_password");
    let client = Client::new(rocket).expect("valid rocket instance");
    let mut req = client.get("/test");
    req.add_header(Header::new(
        "Authorization",
        format!("Basic {}", credentials),
    ));
    let response = req.dispatch();
    assert_eq!(
        file_to_value(INVALID_CREDENTIALS_FILE),
        response_to_value(response)
    );
}

#[test]
fn test_ok() {
    let rocket = start_test_server();
    let credentials = base64::encode(format!("{}:{}", USER, PASSWORD));
    let client = Client::new(rocket).expect("valid rocket instance");
    let mut req = client.get("/test");
    req.add_header(Header::new(
        "Authorization",
        format!("Basic {}", credentials),
    ));
    let response = req.dispatch();
    assert_eq!(file_to_value(OK_FILE), response_to_value(response));
}

#[test]
fn test_excluded() {
    let rocket = start_test_server_with_excludes(vec!["/test"]);
    let client = Client::new(rocket).expect("valid rocket instance");
    let req = client.get("/test");
    let response = req.dispatch();
    assert_eq!(file_to_value(OK_FILE), response_to_value(response));
    let req = client.get("/test2");
    let response = req.dispatch();
    assert_eq!(
        file_to_value(MISSING_HEADER_FILE),
        response_to_value(response)
    );
}

#[test]
fn test_included() {
    let rocket = start_test_server_with_includes(vec!["/test"]);
    let client = Client::new(rocket).expect("valid rocket instance");
    let req = client.get("/test2");
    let response = req.dispatch();
    assert_eq!(file_to_value(OK_FILE), response_to_value(response));
    let req = client.get("/test");
    let response = req.dispatch();
    assert_eq!(
        file_to_value(MISSING_HEADER_FILE),
        response_to_value(response)
    );
}

#[test]
fn test_excluded_glob() {
    let rocket = start_test_server_with_excludes(vec!["/test*"]);
    let client = Client::new(rocket).expect("valid rocket instance");
    let req = client.get("/test");
    let response = req.dispatch();
    assert_eq!(file_to_value(OK_FILE), response_to_value(response));
    let req = client.get("/test2");
    let response = req.dispatch();
    assert_eq!(file_to_value(OK_FILE), response_to_value(response));
    let req = client.get("/other");
    let response = req.dispatch();
    assert_eq!(
        file_to_value(MISSING_HEADER_FILE),
        response_to_value(response)
    );
}

#[test]
fn test_included_glob() {
    let rocket = start_test_server_with_includes(vec!["/test*"]);
    let client = Client::new(rocket).expect("valid rocket instance");
    let req = client.get("/test");
    let response = req.dispatch();
    assert_eq!(
        file_to_value(MISSING_HEADER_FILE),
        response_to_value(response)
    );
    let req = client.get("/test2");
    let response = req.dispatch();
    assert_eq!(
        file_to_value(MISSING_HEADER_FILE),
        response_to_value(response)
    );
    let req = client.get("/other");
    let response = req.dispatch();
    assert_eq!(file_to_value(OK_FILE), response_to_value(response));
}
