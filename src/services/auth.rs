use std::{
    ops::Add,
    time::{Duration, UNIX_EPOCH},
};

use axum::{
    async_trait,
    body::{Body, Bytes},
    extract::{FromRequest, FromRequestParts, Request},
    http::{request::Parts, Response, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, RequestPartsExt, Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{
    decode, encode, errors::ErrorKind, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::debug;

pub fn auth_router() -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/me", get(user_info))
}

async fn user_info(claim: Claim) -> Result<Json<Value>, Json<Value>> {
    Ok(Json(json!({
        "data": "welcome",
        "claim": claim,
    })))
}

async fn login(payload: LoginDto) -> Result<Json<Value>, TokenError> {
    let expired_in = std::time::SystemTime::now() + Duration::new(60 * 60 * 24 * 3, 0);

    match Token::encode(&Claim {
        aud: "ken-app".to_string(),
        sub: payload.email.clone(),
        exp: expired_in.duration_since(UNIX_EPOCH).unwrap().as_secs() as usize, // 2 days
    }) {
        Ok(token) => Ok(Json(json!(LoginDtoResponseSuccess {
            id: "123".to_string(),
            access_token: token,
            email: payload.email,
            token_type: "Bearer".to_string(),
        }))),
        Err(err) => Err(err),
    }
}

async fn register() -> Json<Value> {
    Json(json!({"user": "1", "sign": "up"}))
}

#[derive(Deserialize, Serialize)]
struct LoginDto {
    email: String,
    password: String,
}

enum LoginDtoError {
    FailedParseBody,
    FailedParseJson,
    ValidationFailed(String, String),
}

impl IntoResponse for LoginDtoError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            LoginDtoError::FailedParseBody => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed parse body".to_string(),
            ),
            LoginDtoError::FailedParseJson => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed parse json".to_string(),
            ),
            LoginDtoError::ValidationFailed(field, msg) => {
                let err_msg = format!("Field {} are not valid. {}", &field.as_str(), &msg.as_str());
                (StatusCode::NOT_ACCEPTABLE, err_msg)
            }
        };
        // let body = Json(json!({
        //     "error": error_message,
        // }));
        // (status, body).into_response()

        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

#[async_trait]
impl<S> FromRequest<S> for LoginDto
where
    S: Send + Sync,
{
    type Rejection = LoginDtoError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|_| LoginDtoError::FailedParseBody)?;

        let Json(body_dto) =
            Json::<LoginDto>::from_bytes(&body).map_err(|_| LoginDtoError::FailedParseJson)?;

        if body_dto.email.contains('@') == false {
            return Err(LoginDtoError::ValidationFailed(
                String::from("Email"),
                String::from("Not valid"),
            ));
        }

        // Validation here..

        Ok(body_dto)
    }
}

#[derive(Deserialize, Serialize)]
struct LoginDtoResponseSuccess {
    id: String,
    access_token: String,
    email: String,
    token_type: String,
}

#[derive(Deserialize, Serialize)]
struct LoginDtoResponseError {
    code: String,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claim {
    // Optional. Audience
    aud: String,
    // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    exp: usize,
    // Optional. Subject (whom token refers to)
    sub: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for Claim
where
    S: Send + Sync,
{
    type Rejection = TokenError;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| TokenError::InvalidToken(None))?;

        Token::decode(bearer.token(), &["ken-app"])
    }
}

impl From<Claim> for String {
    fn from(value: Claim) -> Self {
        value.aud
    }
}

#[derive(Debug)]
enum TokenError {
    FilePemNotFound,
    FailedEncodeToken,
    FailedDecodeToken,
    InvalidToken(Option<&'static str>),
}

impl IntoResponse for TokenError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            TokenError::FilePemNotFound => {
                (StatusCode::INTERNAL_SERVER_ERROR, "File PEM not found")
            }
            TokenError::FailedEncodeToken => (StatusCode::INTERNAL_SERVER_ERROR, "Encode failed"),
            TokenError::FailedDecodeToken => (StatusCode::INTERNAL_SERVER_ERROR, "Decode Failed"),
            TokenError::InvalidToken(Some(msg)) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            TokenError::InvalidToken(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

static TOKEN_KEY_PRIV: &[u8] = include_bytes!("../../keypair.pem");
static TOKEN_KEY_PUB: &[u8] = include_bytes!("../../publickey.crt");

struct Token {}

impl Token {
    fn encode(_claim: &Claim) -> Result<String, TokenError> {
        let key = EncodingKey::from_rsa_pem(TOKEN_KEY_PRIV)
            .map_err(|_| TokenError::InvalidToken(None))?;

        encode(&Header::new(jsonwebtoken::Algorithm::RS256), _claim, &key)
            .map_err(|_| TokenError::FailedEncodeToken)
    }

    fn decode(token: &str, expected_audience: &[&str]) -> Result<Claim, TokenError> {
        let key =
            DecodingKey::from_rsa_pem(TOKEN_KEY_PUB).map_err(|_| TokenError::InvalidToken(None))?;
        debug!("Try to decode token : {}", token);

        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&expected_audience);

        let claim = decode::<Claim>(token, &key, &validation)
            .map_err(|op| {
                debug!("Failed decode with error : {}", op);
                match op.into_kind() {
                    ErrorKind::InvalidSignature => TokenError::InvalidToken(None),
                    ErrorKind::InvalidAudience => {
                        TokenError::InvalidToken(Some("Token have Invalid Audience"))
                    }
                    _ => TokenError::FailedDecodeToken,
                }
            })?
            .claims;

        Ok(claim)
    }
}
