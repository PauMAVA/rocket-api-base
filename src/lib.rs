use hmac_sha256::HMAC;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::uri::Origin;
use rocket::{Data, Request};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{from_slice, json};

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
        let signature = parts.get(3).unwrap();
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
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthError {
    MissingHeader,
    InvalidHeaderFormat,
    JWTError(JWTError),
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
        Self {
            secret,
            error_handler: Box::new(error_handler),
            further_checks: if let Some(check) = further_checks {
                Some(Box::new(check))
            } else {
                None
            },
        }
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
