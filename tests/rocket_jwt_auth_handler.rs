#![feature(proc_macro_hygiene, decl_macro)]

use serde::{Deserialize, Serialize};

use rocket::http::uri::Uri;
use rocket::http::{Header, RawStr};
use rocket::local::{Client, LocalResponse};
use rocket::{get, routes, Rocket};
use rocket_api_base::{
    issue_auth_token, new_secret, AuthError, BaseContent, BaseResponse, JWToken, NoContent,
    RocketJWTAuthFairing,
};
use rocket_contrib::json::Json;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::time::SystemTime;

const MISSING_HEADER_FILE: &str = "tests/jwt_auth_handler_missing_header.json";
const INVALID_HEADER_FILE: &str = "tests/jwt_auth_handler_invalid_header.json";
const TAMPERED_TOKEN_FILE: &str = "tests/jwt_auth_handler_tampered_token.json";
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

#[derive(Clone, Serialize, Deserialize)]
struct CustomJWTPayload {
    issue_time: SystemTime,
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

fn further_checks(_token: JWToken<CustomJWTPayload>) -> Result<(), String> {
    Ok(())
}

fn start_test_server() -> (String, Rocket) {
    let secret = new_secret(32);
    (
        secret.clone(),
        rocket::ignite()
            .attach(RocketJWTAuthFairing::<CustomJWTPayload>::new(
                secret,
                auth_error_handler,
                Some(further_checks),
            ))
            .mount(
                "/",
                routes![
                    test_endpoint,
                    test2_endpoint,
                    other_endpoint,
                    auth_error_endpoint
                ],
            ),
    )
}

fn start_test_server_with_excludes(excludes: Vec<&str>) -> (String, Rocket) {
    let secret = new_secret(32);
    (
        secret.clone(),
        rocket::ignite()
            .attach(RocketJWTAuthFairing::<CustomJWTPayload>::new_with_excludes(
                secret,
                auth_error_handler,
                Some(further_checks),
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
            ),
    )
}

fn start_test_server_with_includes(includes: Vec<&str>) -> (String, Rocket) {
    let secret = new_secret(32);
    (
        secret.clone(),
        rocket::ignite()
            .attach(RocketJWTAuthFairing::<CustomJWTPayload>::new_with_includes(
                secret,
                auth_error_handler,
                Some(further_checks),
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
            ),
    )
}

#[test]
fn test_no_header() {
    let (_, rocket) = start_test_server();
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
    let (_, rocket) = start_test_server();
    let client = Client::new(rocket).expect("valid rocket instance");
    let mut req = client.get("/test");
    req.add_header(Header::new("Authorization", "Basic bad_scheme"));
    let response = req.dispatch();
    assert_eq!(
        file_to_value(INVALID_HEADER_FILE),
        response_to_value(response)
    );
}

#[test]
fn test_tampered_token() {
    let (secret, rocket) = start_test_server();
    let mut token = issue_auth_token(
        secret,
        CustomJWTPayload {
            issue_time: SystemTime::now(),
        },
    );
    let client = Client::new(rocket).expect("valid rocket instance");
    let mut req = client.get("/test");
    token.payload.issue_time = SystemTime::now();
    req.add_header(Header::new(
        "Authorization",
        format!("Bearer {}", token.encode()),
    ));
    let response = req.dispatch();
    assert_eq!(
        file_to_value(TAMPERED_TOKEN_FILE),
        response_to_value(response)
    );
}

#[test]
fn test_ok() {
    let (secret, rocket) = start_test_server();
    let token = issue_auth_token(
        secret,
        CustomJWTPayload {
            issue_time: SystemTime::now(),
        },
    );
    let client = Client::new(rocket).expect("valid rocket instance");
    let mut req = client.get("/test");
    req.add_header(Header::new(
        "Authorization",
        format!("Bearer {}", token.encode()),
    ));
    let response = req.dispatch();
    assert_eq!(file_to_value(OK_FILE), response_to_value(response));
}

#[test]
fn test_excluded() {
    let (_, rocket) = start_test_server_with_excludes(vec!["/test"]);
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
    let (_, rocket) = start_test_server_with_includes(vec!["/test"]);
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
    let (_, rocket) = start_test_server_with_excludes(vec!["/test*"]);
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
    let (_, rocket) = start_test_server_with_includes(vec!["/test*"]);
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
