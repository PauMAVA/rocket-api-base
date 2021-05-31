use glob::Pattern;
use hmac_sha256::HMAC;
use rand::distributions::Distribution;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::uri::{Origin, Uri};
use rocket::{Data, Request};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{from_slice, json};
use std::str::FromStr;

#[derive(Serialize)]
pub struct BaseResponse<T>
where
    T: Serialize,
{
    pub result: String,
    pub error_message: String,
    pub error_code: u32,
    pub content: BaseContent<T>,
}

#[derive(Serialize)]
pub struct NoContent {}

pub enum BaseContent<T> {
    Some(T),
    None,
}

impl<T> Serialize for BaseContent<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        match *self {
            BaseContent::Some(ref value) => serializer.serialize_some(value),
            BaseContent::None => serializer.serialize_some(&NoContent {}),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct JWTokenHeader {
    pub alg: String,
    pub typ: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct JWToken<T> {
    pub header: JWTokenHeader,
    pub payload: T,
    pub signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JWTError {
    MalformedToken,
    MalformedEncoding,
    CompromisedIntegrity,
}

impl JWTError {
    pub fn get_message(&self) -> String {
        match *self {
            Self::MalformedToken => "Invalid JWT token format.".into(),
            Self::MalformedEncoding => "Invalid base64 token encoding".into(),
            Self::CompromisedIntegrity => "The token signature does not match and the integrity of the token cannot be verified".into(),
        }
    }

    pub fn get_message_encoded(&self) -> String {
        Uri::percent_encode(&self.get_message()).to_string()
    }
}

fn deserialize_token_component<T>(part: &str) -> Result<T, JWTError>
where
    T: DeserializeOwned,
{
    match base64::decode_config(part, base64::URL_SAFE) {
        Ok(val) => {
            if let Ok(des) = from_slice::<T>(val.as_slice()) {
                Ok(des)
            } else {
                Err(JWTError::MalformedToken)
            }
        }
        Err(_) => Err(JWTError::MalformedEncoding),
    }
}

impl<T> JWToken<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    pub fn decode(secret: String, value: String) -> Result<Self, JWTError> {
        let parts: Vec<String> = value.split('.').map(|x| x.to_string()).collect();
        if parts.len() != 3 {
            return Err(JWTError::MalformedToken);
        }
        let header = deserialize_token_component::<JWTokenHeader>(parts.get(0).unwrap().as_str())?;
        let payload: T = deserialize_token_component::<T>(parts.get(1).unwrap().as_str())?;
        let good_signature = get_base64_signature(secret, &header, &payload);
        let signature = parts.get(2).unwrap();
        if good_signature.as_str() != signature.as_str() {
            return Err(JWTError::CompromisedIntegrity);
        }
        Ok(Self {
            header,
            payload,
            signature: signature.to_string(),
        })
    }

    pub fn encode(&self) -> String {
        format!(
            "{}.{}.{}",
            base64::encode_config(&json!(self.header).to_string(), base64::URL_SAFE),
            base64::encode_config(&json!(self.payload).to_string(), base64::URL_SAFE),
            self.signature
        )
    }
}

struct AlphaNumericSymbols;

impl Distribution<char> for AlphaNumericSymbols {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> char {
        *b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
            .choose(rng)
            .unwrap() as char
    }
}

pub fn new_secret(len: usize) -> String {
    thread_rng()
        .sample_iter(&AlphaNumericSymbols)
        .take(len)
        .collect()
}

pub fn issue_auth_token<T>(secret: String, payload: T) -> JWToken<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    let mut token = JWToken {
        header: JWTokenHeader {
            alg: "HS256".to_string(),
            typ: "JWT".to_string(),
        },
        payload: payload.clone(),
        signature: "".to_string(),
    };
    token.signature = get_base64_signature(secret, &token.header, &payload);
    token
}

fn get_base64_signature<T>(secret: String, header: &JWTokenHeader, payload: &T) -> String
where
    T: Serialize + DeserializeOwned + Clone,
{
    let content = format!(
        "{}.{}",
        base64::encode_config(&json!(header).to_string(), base64::URL_SAFE),
        base64::encode_config(&json!(payload).to_string(), base64::URL_SAFE)
    );
    let slice = HMAC::mac(content.as_bytes(), secret.as_bytes());
    base64::encode_config(&json!(slice).to_string(), base64::URL_SAFE)
}

pub type ErrorHandlerCallback = dyn (Fn(AuthError) -> String) + Send + Sync;
pub type FurtherChecksCallback<T> = dyn (Fn(JWToken<T>) -> Result<(), String>) + Send + Sync;

pub struct RocketJWTAuthFairing<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    secret: String,
    error_handler: Box<ErrorHandlerCallback>,
    further_checks: Option<Box<FurtherChecksCallback<T>>>,
    exclude: Vec<String>,
    include: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthError {
    MissingHeader,
    InvalidHeaderFormat,
    JWTError(JWTError),
    BasicError(BasicError),
}

impl AuthError {
    pub fn get_message(&self) -> String {
        match self {
            &Self::MissingHeader => "The header Authorization is missing".to_string(),
            &Self::InvalidHeaderFormat => {
                "The format of the header data is not valid! Expected: 'Bearer <token>'".to_string()
            }
            Self::JWTError(err) => format!(
                "{} {}",
                "Invalid JWT token!".to_string(),
                &err.get_message()
            ),
            Self::BasicError(err) => format!(
                "{} {}",
                "Invalid Basic auth!".to_string(),
                &err.get_message()
            ),
        }
    }

    pub fn get_message_encoded(&self) -> String {
        Uri::percent_encode(&self.get_message()).to_string()
    }
}

impl<T> RocketJWTAuthFairing<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    pub fn new(
        secret: String,
        error_handler: impl (Fn(AuthError) -> String) + Send + Sync + 'static,
        further_checks: Option<impl (Fn(JWToken<T>) -> Result<(), String>) + Send + Sync + 'static>,
    ) -> Self {
        Self::__new_private(secret, error_handler, further_checks, vec![], vec![])
    }

    pub fn new_with_excludes(
        secret: String,
        error_handler: impl (Fn(AuthError) -> String) + Send + Sync + 'static,
        further_checks: Option<impl (Fn(JWToken<T>) -> Result<(), String>) + Send + Sync + 'static>,
        excludes: Vec<&str>,
    ) -> Self {
        Self::__new_private(secret, error_handler, further_checks, vec![], excludes)
    }

    pub fn new_with_includes(
        secret: String,
        error_handler: impl (Fn(AuthError) -> String) + Send + Sync + 'static,
        further_checks: Option<impl (Fn(JWToken<T>) -> Result<(), String>) + Send + Sync + 'static>,
        includes: Vec<&str>,
    ) -> Self {
        Self::__new_private(secret, error_handler, further_checks, includes, vec![])
    }

    fn __new_private(
        secret: String,
        error_handler: impl (Fn(AuthError) -> String) + Send + Sync + 'static,
        further_checks: Option<impl (Fn(JWToken<T>) -> Result<(), String>) + Send + Sync + 'static>,
        includes: Vec<&str>,
        excludes: Vec<&str>,
    ) -> Self {
        Self {
            secret,
            error_handler: Box::new(error_handler),
            further_checks: if let Some(check) = further_checks {
                Some(Box::new(check))
            } else {
                None
            },
            include: includes.into_iter().map(|x| x.to_string()).collect(),
            exclude: excludes.into_iter().map(|x| x.to_string()).collect(),
        }
    }
}

impl<T> RocketJWTAuthFairing<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    fn must_secure(&self, uri: &Origin) -> bool {
        for include in &self.include {
            if let Ok(pattern) = Pattern::from_str(include) {
                if !pattern.matches(uri.path()) {
                    return false;
                }
            }
        }
        for exclude in &self.exclude {
            if let Ok(pattern) = Pattern::from_str(exclude) {
                if pattern.matches(uri.path()) {
                    return false;
                }
            }
        }
        true
    }
}

impl<T> Fairing for RocketJWTAuthFairing<T>
where
    T: Serialize + DeserializeOwned + Clone + 'static,
{
    fn info(&self) -> Info {
        Info {
            name: "JWT authentication guard",
            kind: Kind::Request,
        }
    }

    fn on_request(&self, request: &mut Request, _: &Data) {
        if !self.must_secure(request.uri()) {
            return;
        }
        if !request.headers().contains("Authorization") {
            let uri = (self.error_handler)(AuthError::MissingHeader);
            request.set_uri(Origin::parse_owned(uri).unwrap());
            return;
        }
        let header_content = request.headers().get_one("Authorization").unwrap();
        if !header_content.starts_with("Bearer ") {
            let uri = (self.error_handler)(AuthError::InvalidHeaderFormat);
            request.set_uri(Origin::parse_owned(uri).unwrap());
            return;
        }
        let token = header_content.replace("Bearer ", "");
        match JWToken::<T>::decode(self.secret.clone(), token) {
            Ok(val) => {
                if let Some(func) = &self.further_checks {
                    if let Err(uri) = func(val) {
                        request.set_uri(Origin::parse_owned(uri).unwrap());
                        return;
                    }
                }
            }
            Err(err) => {
                let uri = (self.error_handler)(AuthError::JWTError(err));
                request.set_uri(Origin::parse_owned(uri).unwrap());
            }
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BasicError {
    MalformedEncoding,
    MalformedFormat,
}

impl BasicError {
    pub fn get_message(&self) -> String {
        match *self {
            Self::MalformedFormat => "Invalid authentication format. Expected user:password".into(),
            Self::MalformedEncoding => "Invalid base64 token encoding".into(),
        }
    }

    pub fn get_message_encoded(&self) -> String {
        Uri::percent_encode(&self.get_message()).to_string()
    }
}

pub type BasicAuthCallback = dyn Fn(String, String) -> Result<(), String> + Send + Sync;

pub struct RocketBasicAuthFairing {
    callback: Box<BasicAuthCallback>,
    error_handler: Box<ErrorHandlerCallback>,
    includes: Vec<String>,
    excludes: Vec<String>,
}

impl RocketBasicAuthFairing {
    pub fn new(
        callback: impl Fn(String, String) -> Result<(), String> + Send + Sync + 'static,
        error_handler: impl (Fn(AuthError) -> String) + Send + Sync + 'static,
    ) -> Self {
        Self::__new_private(callback, error_handler, vec![], vec![])
    }

    pub fn new_with_includes(
        callback: impl Fn(String, String) -> Result<(), String> + Send + Sync + 'static,
        error_handler: impl (Fn(AuthError) -> String) + Send + Sync + 'static,
        includes: Vec<&str>,
    ) -> Self {
        Self::__new_private(callback, error_handler, includes, vec![])
    }

    pub fn new_with_excludes(
        callback: impl Fn(String, String) -> Result<(), String> + Send + Sync + 'static,
        error_handler: impl (Fn(AuthError) -> String) + Send + Sync + 'static,
        excludes: Vec<&str>,
    ) -> Self {
        Self::__new_private(callback, error_handler, vec![], excludes)
    }

    fn __new_private(
        callback: impl Fn(String, String) -> Result<(), String> + Send + Sync + 'static,
        error_handler: impl (Fn(AuthError) -> String) + Send + Sync + 'static,
        includes: Vec<&str>,
        excludes: Vec<&str>,
    ) -> Self {
        Self {
            callback: Box::new(callback),
            error_handler: Box::new(error_handler),
            includes: includes.into_iter().map(|x| x.to_string()).collect(),
            excludes: excludes.into_iter().map(|x| x.to_string()).collect(),
        }
    }

    fn must_secure(&self, uri: &Origin) -> bool {
        for include in &self.includes {
            if let Ok(pattern) = Pattern::from_str(include) {
                if !pattern.matches(uri.path()) {
                    return false;
                }
            }
        }
        for exclude in &self.excludes {
            if let Ok(pattern) = Pattern::from_str(exclude) {
                if pattern.matches(uri.path()) {
                    return false;
                }
            }
        }
        true
    }
}

impl Fairing for RocketBasicAuthFairing {
    fn info(&self) -> Info {
        Info {
            name: "Basic authentication guard",
            kind: Kind::Request,
        }
    }

    fn on_request(&self, request: &mut Request, _: &Data) {
        if !self.must_secure(request.uri()) {
            return;
        }
        if !request.headers().contains("Authorization") {
            let uri = (self.error_handler)(AuthError::MissingHeader);
            request.set_uri(Origin::parse_owned(uri).unwrap());
            return;
        }
        let header_content = request.headers().get_one("Authorization").unwrap();
        if !header_content.starts_with("Basic ") {
            let uri = (self.error_handler)(AuthError::InvalidHeaderFormat);
            request.set_uri(Origin::parse_owned(uri).unwrap());
            return;
        }
        let auth_details = match base64::decode(header_content.replace("Basic ", "")) {
            Ok(val) => String::from_utf8(val).unwrap_or_else(|_| "".to_string()),
            Err(_) => {
                let uri =
                    (self.error_handler)(AuthError::BasicError(BasicError::MalformedEncoding));
                request.set_uri(Origin::parse_owned(uri).unwrap());
                return;
            }
        };
        let split: Vec<&str> = auth_details.split(':').collect();
        if split.len() != 2 {
            let uri = (self.error_handler)(AuthError::BasicError(BasicError::MalformedFormat));
            request.set_uri(Origin::parse_owned(uri).unwrap());
            return;
        }
        match (self.callback)(split[0].to_string(), split[1].to_string()) {
            Ok(_) => {}
            Err(uri) => {
                request.set_uri(Origin::parse_owned(uri).unwrap());
            }
        }
    }
}
