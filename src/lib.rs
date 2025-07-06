use actix_web::body::{EitherBody, MessageBody};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::dev::forward_ready;
use actix_web::http::{header, Method};
use actix_web::web::BytesMut;
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform}, Error, FromRequest, HttpMessage, HttpRequest,
    HttpResponse,
};
#[cfg(feature = "session")]
use actix_session::SessionExt;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::{
    future::{err, ok, LocalBoxFuture, Ready},
    stream::StreamExt,
};
use rand::RngCore;
use std::collections::HashMap;
use std::rc::Rc;

pub const DEFAULT_COOKIE_NAME: &str = "csrf-token";
pub const DEFAULT_FORM_FIELD: &str = "csrf_token";
pub const DEFAULT_HEADER: &str = "X-CSRF-Token";

const TOKEN_LEN: usize = 32;

#[derive(Clone)]
pub enum CsrfStorage {
    #[cfg(feature = "session")]
    Session,
    Cookie,
}

#[derive(Clone)]
pub struct CsrfDoubleSubmitCookieConfig {
    pub storage: CsrfStorage,
    pub cookie_name: String,
    pub form_field: String,
    pub header_name: String,
    pub secure: bool, // same as above
    pub same_site: SameSite,
    pub skip_for: Vec<String>,
    pub on_error: Rc<dyn Fn(&HttpRequest) -> HttpResponse>,
}

impl Default for CsrfDoubleSubmitCookieConfig {
    fn default() -> Self {
        CsrfDoubleSubmitCookieConfig {
            #[cfg(feature = "session")]
            storage: CsrfStorage::Session,
            #[cfg(not(feature = "session"))]
            storage: CsrfStorage::Cookie,
            cookie_name: DEFAULT_COOKIE_NAME.into(),
            form_field: DEFAULT_FORM_FIELD.into(),
            header_name: DEFAULT_HEADER.into(),
            secure: true,
            same_site: SameSite::Strict,
            skip_for: vec![],
            on_error: Rc::new(|_| HttpResponse::Forbidden().body("Invalid CSRF token")),
        }
    }
}

pub struct CsrfDoubleSubmitCookieMiddleware {
    config: CsrfDoubleSubmitCookieConfig,
}

impl CsrfDoubleSubmitCookieMiddleware {
    pub fn new(config: CsrfDoubleSubmitCookieConfig) -> Self {
        Self { config }
    }
}

impl Default for CsrfDoubleSubmitCookieMiddleware {
    fn default() -> Self {
        Self::new(CsrfDoubleSubmitCookieConfig::default())
    }
}

impl<S, B> Transform<S, ServiceRequest> for CsrfDoubleSubmitCookieMiddleware
where
    S: Service<ServiceRequest, Response=ServiceResponse<B>, Error=Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = CsrfDoubleSubmitCookieMiddlewareImpl<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CsrfDoubleSubmitCookieMiddlewareImpl {
            service: Rc::new(service),
            config: self.config.clone(),
        })
    }
}

pub struct CsrfDoubleSubmitCookieMiddlewareImpl<S> {
    service: Rc<S>,
    config: CsrfDoubleSubmitCookieConfig,
}

impl<S, B> Service<ServiceRequest> for CsrfDoubleSubmitCookieMiddlewareImpl<S>
where
    S: Service<ServiceRequest, Response=ServiceResponse<B>, Error=Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let req_path = req.path();
        if self
            .config
            .skip_for
            .iter()
            .any(|prefix| req_path.starts_with(prefix))
        {
            let fut = self.service.call(req);
            return Box::pin(async move { Ok(fut.await?.map_into_left_body()) });
        }

        let (token, store_token): (String, Option<String>) = match self.config.storage {
            #[cfg(feature = "session")]
            CsrfStorage::Session => {
                let session = req.get_session();
                let found = session.get::<String>(&self.config.cookie_name).ok().flatten();
                match found {
                    Some(tok) => (tok, None),
                    None => {
                        let tok = generate_token();
                        (tok.clone(), Some(tok))
                    }
                }
            }
            CsrfStorage::Cookie => {
                let found = req
                    .cookie(&self.config.cookie_name)
                    .map(|c| c.value().to_string());
                match found {
                    Some(tok) => (tok, None),
                    None => {
                        let tok = generate_token();
                        (tok.clone(), Some(tok))
                    }
                }
            }
        };

        req.extensions_mut().insert(CsrfToken(token.clone()));

        #[cfg(feature = "session")]
        let session = req.get_session();

        let is_mutating = matches!(
            *req.method(),
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        );

        if !is_mutating {
            let fut = self.service.call(req);
            let cookie_name = self.config.cookie_name.clone();
            let config = self.config.clone();

            return Box::pin(async move {
                let mut res = fut.await?.map_into_left_body();
                if let Some(new_token) = store_token {
                    match config.storage {
                        #[cfg(feature = "session")]
                        CsrfStorage::Session => {
                            session.insert(&cookie_name, new_token)?;
                        }
                        CsrfStorage::Cookie => {
                            let cookie = Cookie::build(&config.cookie_name, &new_token)
                                .http_only(true)
                                .secure(config.secure)
                                .same_site(config.same_site)
                                .finish();
                            res.response_mut().add_cookie(&cookie)?;
                        }
                    }
                }

                Ok(res)
            });
        }

        let service = Rc::clone(&self.service);
        let config = self.config.clone();

        Box::pin(async move {
            let (http_req, mut payload) = req.into_parts();
            let header_token = http_req
                .headers()
                .get(&config.header_name)
                .and_then(|hv| hv.to_str().ok());

            let mut valid = header_token
                .map(|header_token| eq_csrf_tokens(&token, header_token))
                .unwrap_or(false);

            if !valid {
                if let Some(body_token) =
                    try_to_extract_token_from_body(&http_req, &mut payload, &config).await
                {
                    valid = eq_csrf_tokens(&token, &body_token);
                }
            }

            if !valid {
                let response = (config.on_error)(&http_req);
                return Ok(ServiceResponse::new(http_req, response).map_into_right_body());
            }

            let req = ServiceRequest::from_parts(http_req, payload);
            let mut res = service.call(req).await?.map_into_left_body();

            let status = res.status().as_u16();
            if matches!(status, 200 | 201 | 202 | 204) {
                let new_token = generate_token();
                match config.storage {
                    #[cfg(feature = "session")]
                    CsrfStorage::Session => {
                        session.insert(&config.cookie_name, new_token)?;
                    }
                    CsrfStorage::Cookie => {
                        let cookie = Cookie::build(&config.cookie_name, &new_token)
                            .http_only(true)
                            .secure(config.secure)
                            .same_site(config.same_site)
                            .finish();
                        res.response_mut().add_cookie(&cookie)?;
                    }
                }
            }

            Ok(res)
        })
    }
}

async fn try_to_extract_token_from_body(
    req: &HttpRequest,
    payload: &mut actix_web::dev::Payload,
    config: &CsrfDoubleSubmitCookieConfig,
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
                        .get(&config.form_field)
                        .and_then(|v| v.as_str().map(String::from));
                }
            } else if ct.starts_with("application/x-www-form-urlencoded") {
                if let Ok(form) = serde_urlencoded::from_bytes::<HashMap<String, String>>(&body) {
                    return form.get(&config.form_field).cloned();
                }
            }
        }
    }

    None
}

pub fn generate_token() -> String {
    let mut buf = [0u8; TOKEN_LEN];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn eq_csrf_tokens(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes()) {
        result |= x ^ y;
    }
    result == 0
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