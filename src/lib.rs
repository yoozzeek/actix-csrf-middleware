#[cfg(feature = "actix-session")]
use actix_session::SessionExt;
use actix_utils::future::Either;
use actix_web::body::{EitherBody, MessageBody};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::dev::forward_ready;
use actix_web::http::{Method, header};
use actix_web::web::BytesMut;
use actix_web::{
    Error, FromRequest, HttpMessage, HttpRequest, HttpResponse,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{
    future::{Ready, err, ok},
    ready,
    stream::StreamExt,
};
use hmac::{Hmac, Mac};
use pin_project_lite::pin_project;
use rand::RngCore;
use sha2::Sha256;
use std::{
    collections::HashMap,
    marker::PhantomData,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

pub const PRE_SESSION_COOKIE_NAME: &str = "pre-session";

pub const DEFAULT_SESSION_ID_COOKIE_NAME: &str = "id";
pub const DEFAULT_COOKIE_NAME: &str = "csrf-token";
pub const DEFAULT_FORM_FIELD: &str = "csrf_token";
pub const DEFAULT_HEADER: &str = "X-CSRF-Token";

const TOKEN_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, PartialEq)]
pub enum CsrfPattern {
    #[cfg(feature = "actix-session")]
    SynchronizerToken,
    DoubleSubmitCookie,
}

#[derive(Clone)]
pub struct CsrfDoubleSubmitCookie {
    pub http_only: bool,
    pub secure: bool,
    pub same_site: SameSite,
}

#[derive(Clone)]
pub struct CsrfMiddlewareConfig {
    pub pattern: CsrfPattern,
    pub manual_multipart: bool,
    pub session_id_cookie_name: String,
    pub token_cookie_name: String,
    pub token_form_field: String,
    pub token_header_name: String,
    pub token_cookie_config: Option<CsrfDoubleSubmitCookie>,
    pub secret_key: Option<Vec<u8>>,
    pub skip_for: Vec<String>,
    pub on_error: Rc<dyn Fn(&HttpRequest) -> HttpResponse>,
}

impl CsrfMiddlewareConfig {
    #[cfg(feature = "actix-session")]
    pub fn synchronizer_token() -> Self {
        CsrfMiddlewareConfig {
            pattern: CsrfPattern::SynchronizerToken,
            session_id_cookie_name: DEFAULT_SESSION_ID_COOKIE_NAME.to_string(),
            token_cookie_name: DEFAULT_COOKIE_NAME.into(),
            token_form_field: DEFAULT_FORM_FIELD.into(),
            token_header_name: DEFAULT_HEADER.into(),
            token_cookie_config: None,
            secret_key: None,
            skip_for: vec![],
            on_error: Rc::new(|_| HttpResponse::BadRequest().body("Invalid CSRF token")),
            manual_multipart: false,
        }
    }

    pub fn double_submit_cookie(secret_key: &[u8]) -> Self {
        CsrfMiddlewareConfig {
            pattern: CsrfPattern::DoubleSubmitCookie,
            session_id_cookie_name: DEFAULT_SESSION_ID_COOKIE_NAME.to_string(),
            token_cookie_name: DEFAULT_COOKIE_NAME.into(),
            token_form_field: DEFAULT_FORM_FIELD.into(),
            token_header_name: DEFAULT_HEADER.into(),
            token_cookie_config: Some(CsrfDoubleSubmitCookie {
                http_only: false, // Should be false for double-submit cookie
                secure: true,
                same_site: SameSite::Strict,
            }),
            secret_key: Some(Vec::from(secret_key)),
            skip_for: vec![],
            on_error: Rc::new(|_| HttpResponse::BadRequest().body("Invalid CSRF token")),
            manual_multipart: false,
        }
    }

    pub fn with_multipart(mut self, multipart: bool) -> Self {
        self.manual_multipart = multipart;
        self
    }

    pub fn with_token_cookie_config(mut self, config: CsrfDoubleSubmitCookie) -> Self {
        self.token_cookie_config = Some(config);
        self
    }
}

pub struct CsrfMiddleware {
    config: CsrfMiddlewareConfig,
}

impl CsrfMiddleware {
    pub fn new(config: CsrfMiddlewareConfig) -> Self {
        Self { config }
    }
}

impl<S, B> Transform<S, ServiceRequest> for CsrfMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = CsrfMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CsrfMiddlewareService {
            service: Rc::new(service),
            config: self.config.clone(),
        })
    }
}

pub struct CsrfMiddlewareService<S> {
    service: Rc<S>,
    config: CsrfMiddlewareConfig,
}

impl<S> CsrfMiddlewareService<S> {
    fn get_session_id(&self, req: &ServiceRequest) -> (String, bool) {
        if let Some(id) = req
            .cookie(&self.config.session_id_cookie_name)
            .map(|c| c.value().to_string())
        {
            (id, false)
        } else if let Some(id) = req
            .cookie(PRE_SESSION_COOKIE_NAME)
            .map(|c| c.value().to_string())
        {
            (id, false)
        } else {
            (generate_random_token(), true)
        }
    }

    #[cfg(feature = "actix-session")]
    fn get_token_from_session(&self, req: &ServiceRequest) -> (String, bool) {
        let session = req.get_session();
        let found = session
            .get::<String>(&self.config.token_cookie_name)
            .ok()
            .flatten();
        match found {
            Some(tok) => (tok, false),
            None => (generate_random_token(), true),
        }
    }

    fn get_token_from_cookie(&self, session_id: &str, req: &ServiceRequest) -> (String, bool) {
        let token = {
            req.cookie(&self.config.token_cookie_name)
                .map(|c| c.value().to_string())
        };

        match token {
            Some(tok) => (tok, false),
            None => {
                let secret = self
                    .config
                    .secret_key
                    .as_ref()
                    .expect("Secret key is set for double submit cookie pattern");
                let tok = generate_hmac_token(session_id, secret);
                (tok.clone(), true)
            }
        }
    }
}

impl<S, B> Service<ServiceRequest> for CsrfMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Either<CsrfResponse<S, B>, Ready<Result<Self::Response, Self::Error>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let req_path = req.path();
        if self
            .config
            .skip_for
            .iter()
            .any(|prefix| req_path.starts_with(prefix))
        {
            return Either::left(CsrfResponse {
                fut: self.service.call(req),
                #[cfg(feature = "actix-session")]
                session: None,
                config: self.config.clone(),
                token: String::new(),
                is_mutating: false,
                should_set_token: false,
                cookie_session: None,
                _phantom: PhantomData,
            });
        }

        #[cfg(feature = "actix-session")]
        let session = req.get_session();

        let (token, should_set_token, cookie_session): (String, bool, Option<(String, bool)>) =
            match self.config.pattern {
                CsrfPattern::DoubleSubmitCookie => {
                    let (session_id, should_set_session) = self.get_session_id(&req);
                    let (cookie_token, should_set_token) =
                        self.get_token_from_cookie(&session_id, &req);
                    (
                        cookie_token,
                        should_set_token,
                        Some((session_id, should_set_session)),
                    )
                }
                #[cfg(feature = "actix-session")]
                CsrfPattern::SynchronizerToken => {
                    let (token, set_token) = self.get_token_from_session(&req);
                    (token, set_token, None)
                }
            };

        req.extensions_mut().insert(CsrfToken(token.clone()));

        let is_mutating = !matches!(
            *req.method(),
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        );

        Either::left(CsrfResponse {
            fut: self.service.call(req),
            #[cfg(feature = "actix-session")]
            session: Some(session),
            config: self.config.clone(),
            token,
            is_mutating,
            should_set_token,
            cookie_session,
            _phantom: PhantomData,
        })
    }
}

async fn token_from_body(
    req: &HttpRequest,
    payload: &mut actix_web::dev::Payload,
    config: &CsrfMiddlewareConfig,
) -> Option<String> {
    let mut body = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        match chunk {
            Ok(bytes) => body.extend_from_slice(&bytes),
            Err(_) => return None,
        }
    }
    *payload = actix_web::dev::Payload::from(body.clone().freeze());

    if let Some(ct) = req.headers().get(header::CONTENT_TYPE) {
        if let Ok(ct) = ct.to_str() {
            if ct.starts_with("application/json") {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
                    return json
                        .get(&config.token_form_field)
                        .and_then(|v| v.as_str().map(String::from));
                }
            } else if ct.starts_with("application/x-www-form-urlencoded") {
                if let Ok(form) = serde_urlencoded::from_bytes::<HashMap<String, String>>(&body) {
                    return form.get(&config.token_form_field).cloned();
                }
            }
        }
    }

    None
}

pin_project! {
    pub struct CsrfResponse<S, B>
    where
        S: Service<ServiceRequest>,
        B: MessageBody,
    {
        #[pin]
        fut: S::Future,
        session: Option<actix_session::Session>,
        config: CsrfMiddlewareConfig,
        token: String,
        is_mutating: bool,
        should_set_token: bool,
        cookie_session: Option<(String, bool)>,
        _phantom: PhantomData<B>,
    }
}

impl<S, B> Future for CsrfResponse<S, B>
where
    B: MessageBody,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
{
    type Output = Result<ServiceResponse<EitherBody<B>>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().project();
        let session = this.session.as_ref().expect("Session should be present");
        let cookie_session = this.cookie_session.as_ref();
        match ready!(this.fut.poll(cx)) {
            Ok(mut resp) => Poll::Ready(Ok(resp.map_body(async move |head, body| {
                // head.headers_mut();
                // read requests

                let config = this.config;

                if *this.is_mutating && *this.should_set_token {
                    match &config.pattern {
                        #[cfg(feature = "actix-session")]
                        CsrfPattern::SynchronizerToken => session
                            .insert(&this.config.token_cookie_name, &this.token)
                            .map_err(actix_web::error::ErrorInternalServerError)?,
                        CsrfPattern::DoubleSubmitCookie => {
                            let cookie_config = match &config.token_cookie_config {
                                Some(config) => config,
                                None => {
                                    return Err(actix_web::error::ErrorInternalServerError(
                                        "token cookie config is not set",
                                    ));
                                }
                            };

let token_cookie = Cookie::build(&config.token_cookie_name, &*this.token)
                                .http_only(cookie_config.http_only)
                                .secure(cookie_config.secure)
                                .same_site(cookie_config.same_site)
                                .finish();

                            resp.response_mut()
                                .add_cookie(&token_cookie)
                                .map_err(actix_web::error::ErrorInternalServerError)?;

                            // set pre-session
                            if let Some((pre_session_id, should_set)) = this.cookie_session {
                                if *should_set {
                                    resp.response_mut()
                                        .add_cookie(
&Cookie::build(
                                                PRE_SESSION_COOKIE_NAME,
                                                &**pre_session_id,
                                            )
                                            .http_only(cookie_config.http_only)
                                            .secure(cookie_config.secure)
                                            .same_site(cookie_config.same_site)
                                            .finish(),
                                        )
                                        .map_err(actix_web::error::ErrorInternalServerError)?;
                                }
                            }
                        }
                    }
                }

                // process mutating request
// process mutating request
                if !*this.is_mutating {
                    return Ok(EitherBody::left(body));
                }
                let session_id = if let Some((id, _should_set)) = cookie_session {
                    Some(id)
                } else {
                    None
                };

                // handle manual multipart form data
                if let Some(ct) = http_req
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|hv| hv.to_str().ok())
                {
                    if ct.starts_with("multipart/form-data") {
                        if !config.manual_multipart {
                            return Err(actix_web::error::ErrorBadRequest(
                                "multipart form data is not enabled by csrf config",
                            ));
                        }

                        let req = ServiceRequest::from_parts(http_req, payload);
                        let res = service.call(req).await?.map_into_left_body();
                        return Ok(res);
                    }
                }

                // try to extract token from header or form data
                let client_token = if let Some(header_token) = http_req
                    .headers()
                    .get(&config.token_header_name)
                    .and_then(|hv| hv.to_str().ok())
                {
                    header_token.to_string()
                } else if let Some(body_token) =
                    token_from_body(&http_req, &mut payload, &config).await
                {
                    body_token
                } else {
                    return Err(actix_web::error::ErrorBadRequest(
                        "csrf token is not present in request",
                    ));
                };

let valid = match config.pattern {
                    #[cfg(feature = "actix-session")]
                    CsrfPattern::SynchronizerToken => {
                        eq_tokens(client_token.as_bytes(), this.token.as_bytes())
                    }
                    CsrfPattern::DoubleSubmitCookie => {
                        if let Some(id) = session_id {
                            let secret = match config.secret_key.as_ref() {
                                Some(secret) => secret,
                                None => {
                                    return Err(actix_web::error::ErrorInternalServerError(
                                        "csrf cookie secret is not set",
                                    ));
                                }
                            };
                            validate_hmac_token(&id, &client_token, secret)?
                        } else {
                            return Err(actix_web::error::ErrorInternalServerError(
                                "session or pre-session id is not set",
                            ));
                        }
                    }
                };

                if !valid {
                    let response = (config.on_error)(&http_req);
                    return Ok(ServiceResponse::new(http_req, response).map_into_right_body());
                }

                let req = ServiceRequest::from_parts(http_req, payload);
                let mut res = service.call(req).await?.map_into_left_body();

                // refresh token after successful mutation
                let status = res.status().as_u16();
                if matches!(status, 200 | 201 | 202 | 204) {
                    let new_token = generate_random_token();
                    match config.pattern {
                        #[cfg(feature = "actix-session")]
                        CsrfPattern::SynchronizerToken => session
                            .insert(config.token_cookie_name.clone(), new_token)
                            .map_err(actix_web::error::ErrorInternalServerError)?,
                        CsrfPattern::DoubleSubmitCookie => {
                            if let Some(cfg) = config.token_cookie_config {
                                res.response_mut()
                                    .add_cookie(
                                        &Cookie::build(&config.token_cookie_name, &new_token)
                                            .http_only(cfg.http_only)
                                            .secure(cfg.secure)
                                            .same_site(cfg.same_site)
                                            .finish(),
                                    )
                                    .map_err(actix_web::error::ErrorInternalServerError)?;
                            }
                        }
                    }
                }

Ok(EitherBody::left(body))
            }))),
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

#[derive(Clone)]
pub struct CsrfToken(pub String);

impl FromRequest for CsrfToken {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        match req.extensions().get::<CsrfToken>() {
            Some(token) => ok(token.clone()),
            None => {
                log::error!("CsrfToken extractor used without CSRF middleware");
                err(actix_web::error::ErrorInternalServerError(
                    "CSRF middleware is not configured",
                ))
            }
        }
    }
}

pub fn generate_random_token() -> String {
    let mut buf = [0u8; TOKEN_LEN];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn eq_tokens(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0;
    for (x, y) in a.iter().zip(b) {
        result |= x ^ y;
    }
    result == 0
}

pub fn generate_hmac_token(session_id: &str, secret: &[u8]) -> String {
    let tok = generate_random_token();
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    let message = format!("{}!{}", session_id, tok);
    mac.update(message.as_bytes());

    let hmac_hex = hex::encode(mac.finalize().into_bytes());
    format!("{}.{}", hmac_hex, tok)
}

pub fn validate_hmac_token(session_id: &str, token: &str, secret: &[u8]) -> Result<bool, Error> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        return Ok(false);
    }
    let (hmac_hex, csrf_token) = (parts[0], parts[1]);

    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(actix_web::error::ErrorInternalServerError)?;
    let message = format!("{}!{}", session_id, csrf_token);
    mac.update(message.as_bytes());
    let expected_hmac = mac.finalize().into_bytes();

    let hmac_bytes = hex::decode(hmac_hex).map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(eq_tokens(&expected_hmac, &hmac_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION_ID: &str = "test";
    const SECRET: &str = "secret";

    #[test]
    fn test_generate_and_validate_hmac_token() {
        let token = generate_hmac_token(SESSION_ID, SECRET.as_bytes());
        let res = validate_hmac_token(SESSION_ID, &token, SECRET.as_bytes());
        assert!(res.unwrap());
    }

    #[test]
    fn test_handle_invalid_hmac_token() {
        let token = generate_hmac_token(SESSION_ID, SECRET.as_bytes());
        let res = validate_hmac_token(SESSION_ID, &token, SECRET.as_bytes());
        assert!(res.unwrap());
    }
}
