use actix_http::{StatusCode, header::HeaderMap};
#[cfg(feature = "actix-session")]
use actix_session::SessionExt;
use actix_utils::future::Either;
use actix_web::{
    Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, HttpResponseBuilder, ResponseError,
    body::{EitherBody, MessageBody},
    cookie::{Cookie, SameSite, time},
    dev::forward_ready,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::{Method, header},
    web::BytesMut,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{
    future::{Ready, err, ok},
    ready,
    stream::StreamExt,
};
use hmac::{Hmac, KeyInit, Mac};
use log::{error, warn};
use pin_project_lite::pin_project;
use rand::Rng;
use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, Visitor};
use sha2::Sha256;
use std::{
    error, fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};
use subtle::ConstantTimeEq;
use url::Url;

/// Rotate or tear down CSRF state in a response,
/// as an extension on [`HttpRequest`].
///
/// Pulls the config from request extensions,
/// leaving handlers nothing to pass. Use
/// [`rotate_csrf_after_login`](Self::rotate_csrf_after_login)
/// on authentication (anonymous -> authorized) and
/// [`rotate_csrf_after_logout`](Self::rotate_csrf_after_logout)
/// on deauthentication (authorized teardown).
///
/// # Examples
/// ```
/// use actix_csrf_middleware::CsrfRequestExt;
/// use actix_web::{HttpRequest, HttpResponse};
///
/// async fn after_login(req: HttpRequest) -> actix_web::Result<HttpResponse> {
///     let mut resp = HttpResponse::Ok();
///     req.rotate_csrf_after_login("user-session-id", &mut resp)?;
///     Ok(resp.finish())
/// }
///
/// async fn after_logout(req: HttpRequest) -> actix_web::Result<HttpResponse> {
///     let mut resp = HttpResponse::Ok();
///     req.rotate_csrf_after_logout(&mut resp)?;
///     Ok(resp.finish())
/// }
/// ```
pub trait CsrfRequestExt {
    /// Upgrade anonymous CSRF state to authorized:
    /// mints a fresh authorized token bound to
    /// `session_id` and expires the anonymous and
    /// pre-session markers. Call after a successful
    /// login or privilege escalation, once the
    /// session id cookie is set.
    fn rotate_csrf_after_login(
        &self,
        session_id: &str,
        resp: &mut HttpResponseBuilder,
    ) -> Result<(), Error>;

    /// Tear down authorized CSRF state: expires
    /// the session id cookie, the authorized and
    /// anonymous token cookies, and the pre-session
    /// marker, and suppresses the middleware's
    /// post-mutation token refresh for this
    /// response. Call on logout. The next anonymous
    /// request re-mints a fresh pre-session /
    /// anonymous token pair.
    fn rotate_csrf_after_logout(&self, resp: &mut HttpResponseBuilder) -> Result<(), Error>;
}

/// Default name of the authorized CSRF token bucket.
///
/// Double-Submit Cookie: cookie storing the authorized token.
///
/// Synchronizer Token (`actix-session`): session key for the token.
///
/// Override with [`CsrfMiddlewareConfig::token_cookie_name`].
pub const DEFAULT_CSRF_TOKEN_KEY: &str = "CSRF";

/// Default cookie name for anonymous (pre-session)
/// tokens, Double-Submit Cookie pattern.
///
/// Lets clients perform allowed mutations
/// (e.g. registration) before authentication.
/// Under the Synchronizer Token pattern
/// anonymous tokens live server-side in
/// [`CsrfMiddlewareConfig::anon_session_key_name`] instead.
///
/// Override with [`CsrfMiddlewareConfig::anon_token_cookie_name`].
pub const DEFAULT_CSRF_ANON_TOKEN_KEY: &str = "CSRF-ANON";

/// Default body field for the CSRF token
/// when no header is present.
///
/// Read from `application/json` and
/// `application/x-www-form-urlencoded` bodies.
/// `multipart/form-data` bodies are never scanned:
/// such requests get 400 unless the path is listed
/// in [`CsrfMiddlewareConfig::with_multipart`].
///
/// Override with [`CsrfMiddlewareConfig::token_form_field`].
pub const DEFAULT_CSRF_TOKEN_FIELD: &str = "csrf_token";

/// Default header carrying the CSRF token.
///
/// Checked before the body field
/// [`DEFAULT_CSRF_TOKEN_FIELD`] on mutating requests.
///
/// Override with [`CsrfMiddlewareConfig::token_header_name`].
pub const DEFAULT_CSRF_TOKEN_HEADER: &str = "X-CSRF-Token";

/// Default session id cookie; binds tokens
/// and signals authorization state.
///
/// Double-Submit Cookie: mixed into HMAC derivation,
/// which lets the server verify token provenance.
/// Synchronizer Token: its presence marks an
/// authenticated session, with the token value
/// held server-side under `token_cookie_name`.
///
/// `actix-session` also defaults to `id`; sharing it
/// marks every request authorized. Rename one of them.
///
/// Override with [`CsrfMiddlewareConfig::session_id_cookie_name`].
pub const DEFAULT_SESSION_ID_KEY: &str = "id";

/// Pre-session cookie minted
/// for unauthenticated flows.
///
/// HMAC-signed by the server
/// (`encode_pre_session_cookie` /
/// `decode_pre_session_cookie`) to give a stable
/// identifier before a real session exists,
/// enabling anonymous tokens and a clean upgrade
/// to authorized tokens after login. It is always
/// HttpOnly and SameSite=Strict; its Secure flag
/// follows [`CsrfMiddlewareConfig::secure`],
/// shared with every other cookie the middleware
/// sets. Removed once the request is associated
/// with an authorized session.
pub const CSRF_PRE_SESSION_KEY: &str = "pre-session";

/// Pre-session cookie is HttpOnly, out of reach
/// of client scripts, limiting token exfiltration.
/// Not configurable by design.
const PRE_SESSION_HTTP_ONLY: bool = true;

/// Pre-session cookie is SameSite=Strict,
/// minimizing cross-site sending. Not configurable.
const PRE_SESSION_SAME_SITE: SameSite = SameSite::Strict;

/// Raw random token size in bytes.
///
/// 32 bytes (256 bits), base64url-encoded without
/// padding to a 43-char ASCII string. Changing it
/// alters the public token shape and is not supported.
const TOKEN_LEN: usize = 32;

const TOKEN_B64_LEN: usize = TOKEN_LEN.div_ceil(3) * 4 - (3 - TOKEN_LEN % 3) % 3;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

type HmacSha256 = Hmac<Sha256>;

/// Classification of CSRF tokens by context.
///
/// Keeps the two apart: an anonymous token is
/// never accepted on an authenticated endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenClass {
    /// Pre-session, not yet authenticated.
    Anonymous,
    /// Bound to an authenticated session id.
    Authorized,
}

impl TokenClass {
    fn as_str(&self) -> &'static str {
        match self {
            TokenClass::Anonymous => "anon",
            TokenClass::Authorized => "auth",
        }
    }
}

#[derive(Clone, Copy, Default)]
struct CookieState {
    dup_token: bool,
    dup_anon_token: bool,
    dup_pre_session: bool,
    has_pre_session: bool,
    has_token: bool,
    has_anon_token: bool,
    pre_session_regenerated: bool,
}

impl CookieState {
    fn any_duplicate(self) -> bool {
        self.dup_token || self.dup_anon_token || self.dup_pre_session
    }
}

struct MatchKey<'a>(&'a str);

impl<'de> DeserializeSeed<'de> for MatchKey<'_> {
    type Value = bool;

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for MatchKey<'_> {
    type Value = bool;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object key")
    }

    fn visit_str<E: de::Error>(self, key: &str) -> Result<Self::Value, E> {
        Ok(key == self.0)
    }
}

struct TokenFromMap<'a>(&'a str);

impl<'de> DeserializeSeed<'de> for TokenFromMap<'_> {
    type Value = Option<String>;

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for TokenFromMap<'_> {
    type Value = Option<String>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a json object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut found = None;
        while let Some(matched) = map.next_key_seed(MatchKey(self.0))? {
            match matched {
                true => found = Some(map.next_value()?),
                false => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(found)
    }
}

/// Path matcher for [`CsrfMiddlewareConfig::with_multipart`].
///
/// Matched against the raw pre-routing path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultipartRoute {
    Exact(String),

    /// Matches at a segment boundary: `/files`
    /// covers `/files/1/raw`, never `/filesystem`.
    Prefix(String),
}

impl MultipartRoute {
    fn path(&self) -> &str {
        match self {
            MultipartRoute::Exact(path) | MultipartRoute::Prefix(path) => path,
        }
    }

    fn matches(&self, req_path: &str) -> bool {
        match self {
            MultipartRoute::Exact(path) => path == req_path,
            MultipartRoute::Prefix(path) => {
                let prefix = path.strip_suffix('/').unwrap_or(path);

                req_path
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
            }
        }
    }
}

/// Marker put in request extensions by
/// [`rotate_csrf_after_logout`] to tell the
/// response path to skip its post-mutation
/// token refresh.
///
/// Without it, a logout over a mutating method
/// (POST) would have the middleware append a fresh
/// authorized token cookie after the handler
/// expired it; the later `Set-Cookie` wins in the
/// browser and the teardown is silently undone.
struct CsrfTeardown;

/// Reason a request was rejected by [`CsrfMiddleware`].
///
/// Implements [`ResponseError`], rendering by default
/// as `{"error":"<code>"}` (see [`code`]) with
/// the status in [`status_code`], `Content-Type:
/// application/json`. A copy is stored in the response
/// extensions, letting an app's `ErrorHandlers` recover it
/// with `res.response().extensions().get::<CsrfError>()`
/// and re-render in its own shape.
///
/// [`code`]: CsrfError::code
/// [`status_code`]: ResponseError::status_code
/// [`ResponseError`]: ResponseError
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsrfError {
    /// No token in the configured header or body
    /// field on a mutating request. `400`.
    TokenMissing,

    /// Token present but failed verification. `400`.
    TokenInvalid,

    /// Origin/Referer rejected by strict
    /// enforcement. `403`.
    OriginRejected,

    /// `multipart/form-data` request to
    /// a path not matched by any route in
    /// [`CsrfMiddlewareConfig::with_multipart`]. `400`.
    MultipartNotAllowed,

    /// Body exceeded `max_body_bytes` before the
    /// token could be read. `413`.
    BodyTooLarge,

    /// Request body could not be read. `400`.
    BodyRead,

    /// Middleware fault. `500`. The body is generic;
    /// the cause is logged server-side and never sent
    /// to the client.
    Internal,
}

impl CsrfError {
    /// Stable, machine-readable code for the rejection.
    pub fn code(self) -> &'static str {
        match self {
            CsrfError::TokenMissing => "csrf_token_missing",
            CsrfError::TokenInvalid => "csrf_token_invalid",
            CsrfError::OriginRejected => "csrf_origin_rejected",
            CsrfError::MultipartNotAllowed => "csrf_multipart_not_allowed",
            CsrfError::BodyTooLarge => "csrf_body_too_large",
            CsrfError::BodyRead => "csrf_body_read_error",
            CsrfError::Internal => "csrf_internal_error",
        }
    }
}

impl fmt::Display for CsrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl error::Error for CsrfError {}

impl ResponseError for CsrfError {
    fn status_code(&self) -> StatusCode {
        match self {
            CsrfError::OriginRejected => StatusCode::FORBIDDEN,
            CsrfError::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            CsrfError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            CsrfError::TokenMissing
            | CsrfError::TokenInvalid
            | CsrfError::MultipartNotAllowed
            | CsrfError::BodyRead => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let mut resp = HttpResponse::build(self.status_code())
            .content_type("application/json")
            .body(format!(r#"{{"error":"{}"}}"#, self.code()));

        resp.extensions_mut().insert(*self);

        resp
    }
}

/// CSRF defense patterns for [`CsrfMiddleware`].
///
/// `DoubleSubmitCookie`: HMAC-protected token in
/// a cookie, echoed back via header or form/json
/// field. No server-side session storage.
///
/// `SynchronizerToken`: random token held
/// server-side in a session (`actix-session`),
/// echoed back by the client.
///
/// See [`CsrfMiddlewareConfig`] constructors for examples.
#[derive(Clone, PartialEq)]
pub enum CsrfPattern {
    /// Store tokens server-side in session
    /// storage (requires `actix-session`).
    #[cfg(feature = "actix-session")]
    SynchronizerToken,

    /// Store tokens client-side in
    /// cookies and verify with HMAC.
    DoubleSubmitCookie,
}

/// Cookie flags for Double-Submit Cookie tokens.
///
/// `http_only` must be `false` for client code to
/// read the token and mirror it into a header or
/// form field. `same_site` is `Strict` or `Lax`
/// per cross-site needs. The `Secure` flag is
/// not here: it is shared across every cookie the
/// middleware sets via [`CsrfMiddlewareConfig::secure`].
#[derive(Clone)]
pub struct CsrfDoubleSubmitCookie {
    pub http_only: bool,
    pub same_site: SameSite,
}

/// Extractor for the current CSRF token.
///
/// - Safe requests (GET/HEAD): ensures a token
///   exists and exposes it to the handler.
/// - Mutating requests (POST/PUT/PATCH/DELETE):
///   extracting [`CsrfToken`] verifies the token
///   first; on failure the request is rejected
///   and the handler does not run.
///
/// # Examples
/// Read the token in a handler and embed it
/// into the rendered HTML or JSON.
/// ```
/// use actix_csrf_middleware::CsrfToken;
/// use actix_web::{HttpResponse, Responder};
///
/// async fn form(csrf: CsrfToken) -> impl Responder {
///     HttpResponse::Ok().body(format!("token:{}", csrf.0))
/// }
/// ```
///
/// Requires the middleware to be installed via
/// [`CsrfMiddleware::new`]; otherwise extraction
/// fails with an internal error.
#[derive(Clone)]
pub struct CsrfToken(pub String);

impl FromRequest for CsrfToken {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        match req.extensions().get::<CsrfToken>() {
            Some(token) => ok(token.clone()),
            None => {
                error!("CsrfToken extracted without CsrfMiddleware installed");
                err(CsrfError::Internal.into())
            }
        }
    }
}

/// Configuration for [`CsrfMiddleware`].
///
/// Pick a defense pattern and tune token locations,
/// cookie names, content-type handling, and origin checks.
/// Construct with [`double_submit_cookie`](Self::double_submit_cookie)
/// or, with `actix-session`, [`synchronizer_token`](Self::synchronizer_token).
///
/// # Defaults
/// - Token header: [`DEFAULT_CSRF_TOKEN_HEADER`]
/// - Token field: [`DEFAULT_CSRF_TOKEN_FIELD`]
/// - Session cookie: [`DEFAULT_SESSION_ID_KEY`]
/// - Max body scanned for token: 2 MiB
///
/// # Security
/// - Double-Submit Cookie: the token cookie must
///   be client-readable (`http_only = false`) to
///   be mirrored into the header.
/// - Keep `secure = true` (the default) in
///   production; only disable it for local HTTP.
/// - Enable [`with_enforce_origin`](Self::with_enforce_origin)
///   to mitigate CSRF even if a token leaks.
/// - Avoid `multipart/form-data` unless you can
///   extract the token manually.
#[derive(Clone)]
pub struct CsrfMiddlewareConfig {
    pub pattern: CsrfPattern,
    pub multipart_routes: Vec<MultipartRoute>,
    pub session_id_cookie_name: String,

    /// `Secure` flag applied to every cookie
    /// the middleware sets (pre-session and
    /// token cookies alike). `true` by default.
    /// Set `false` only for local HTTP.
    pub secure: bool,

    /// `Domain` applied to every cookie the
    /// middleware sets. `None` (default) keeps
    /// cookies host-only. Set a parent like
    /// `.example.com` to share across subdomains.
    ///
    /// Widens the CSRF trust boundary to every
    /// subdomain; read [`with_cookie_domain`] first.
    ///
    /// [`with_cookie_domain`]: CsrfMiddlewareConfig::with_cookie_domain
    pub domain: Option<String>,

    /// Authorized (session-bound) tokens.
    pub token_cookie_name: String,

    /// Anonymous (pre-session) tokens.
    pub anon_token_cookie_name: String,

    /// Anonymous (pre-session) token
    /// key for SynchronizerToken.
    #[cfg(feature = "actix-session")]
    pub anon_session_key_name: String,
    pub token_form_field: String,
    pub token_header_name: String,
    pub token_cookie_config: Option<CsrfDoubleSubmitCookie>,
    pub secret_key: zeroize::Zeroizing<Vec<u8>>,
    pub skip_for: Vec<String>,

    /// Enforce Origin/Referer checks
    /// for mutating requests.
    pub enforce_origin: bool,

    /// Allowed origins `scheme://host[:port]`
    /// when `enforce_origin` is true.
    pub allowed_origins: Vec<String>,

    /// Maximum allowed body bytes to read when
    /// extracting CSRF tokens from body
    /// (POST/PUT/PATCH/DELETE).
    pub max_body_bytes: usize,
}

impl CsrfMiddlewareConfig {
    /// Configuration for the Synchronizer Token pattern.
    ///
    /// Tokens are stored server-side in the session
    /// via `actix-session` and compared against the
    /// value the client presents.
    ///
    /// # Examples
    /// Cookie-based sessions (needs the `actix-session` feature):
    /// ```ignore
    /// use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig};
    /// use actix_session::{SessionMiddleware, storage::CookieSessionStore};
    /// use actix_web::{App, cookie::Key};
    ///
    /// let secret = b"a-very-long-application-secret-key-of-32+bytes";
    /// let cfg = CsrfMiddlewareConfig::synchronizer_token(secret);
    /// let app = App::new()
    ///     .wrap(SessionMiddleware::new(CookieSessionStore::default(), Key::generate()))
    ///     .wrap(CsrfMiddleware::new(cfg));
    /// ```
    #[cfg(feature = "actix-session")]
    pub fn synchronizer_token(secret_key: &[u8]) -> Self {
        check_secret_key(secret_key);

        CsrfMiddlewareConfig {
            pattern: CsrfPattern::SynchronizerToken,
            session_id_cookie_name: DEFAULT_SESSION_ID_KEY.to_string(),
            token_cookie_name: DEFAULT_CSRF_TOKEN_KEY.into(),
            anon_token_cookie_name: DEFAULT_CSRF_ANON_TOKEN_KEY.into(),
            #[cfg(feature = "actix-session")]
            anon_session_key_name: format!("{DEFAULT_CSRF_TOKEN_KEY}-anon"),
            token_form_field: DEFAULT_CSRF_TOKEN_FIELD.into(),
            token_header_name: DEFAULT_CSRF_TOKEN_HEADER.into(),
            token_cookie_config: None,
            secret_key: zeroize::Zeroizing::new(secret_key.into()),
            skip_for: vec![],
            multipart_routes: Vec::new(),
            secure: true,
            domain: None,
            enforce_origin: false,
            allowed_origins: vec![],
            max_body_bytes: 2 * 1024 * 1024, // 2 MiB default
        }
    }

    /// Configuration for the Double-Submit Cookie pattern.
    ///
    /// The token sits in a cookie and is echoed by the client
    /// in a header or form field. Its integrity is protected
    /// by an HMAC bound to the session id and the token.
    ///
    /// # Examples
    /// ```
    /// use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig};
    /// use actix_web::{App};
    ///
    /// let secret = b"a-very-long-application-secret-key-of-32+bytes";
    /// let cfg = CsrfMiddlewareConfig::double_submit_cookie(secret);
    /// let app = App::new().wrap(CsrfMiddleware::new(cfg));
    /// ```
    pub fn double_submit_cookie(secret_key: &[u8]) -> Self {
        check_secret_key(secret_key);

        CsrfMiddlewareConfig {
            pattern: CsrfPattern::DoubleSubmitCookie,
            session_id_cookie_name: DEFAULT_SESSION_ID_KEY.to_string(),
            token_cookie_name: DEFAULT_CSRF_TOKEN_KEY.into(),
            anon_token_cookie_name: DEFAULT_CSRF_ANON_TOKEN_KEY.into(),
            #[cfg(feature = "actix-session")]
            anon_session_key_name: format!("{DEFAULT_CSRF_TOKEN_KEY}-anon"),
            token_form_field: DEFAULT_CSRF_TOKEN_FIELD.into(),
            token_header_name: DEFAULT_CSRF_TOKEN_HEADER.into(),
            token_cookie_config: Some(CsrfDoubleSubmitCookie {
                http_only: false, // Should be false for double-submit cookie
                same_site: SameSite::Strict,
            }),
            secret_key: zeroize::Zeroizing::new(secret_key.into()),
            skip_for: vec![],
            multipart_routes: Vec::new(),
            secure: true,
            domain: None,
            enforce_origin: false,
            allowed_origins: vec![],
            max_body_bytes: 2 * 1024 * 1024,
        }
    }

    /// Exempt these routes from multipart token
    /// extraction; their handlers must validate it.
    /// Every other path rejects multipart with 400.
    ///
    /// # Panics
    /// If a route can never match a request path,
    /// or a `Prefix` would exempt every path.
    pub fn with_multipart(mut self, routes: Vec<MultipartRoute>) -> Self {
        for route in &routes {
            check_multipart_route(route);
        }

        self.multipart_routes = routes;

        self
    }

    /// Max request body bytes read when searching
    /// for a CSRF token in JSON or url-encoded
    /// bodies. Defaults to 2 MiB.
    pub fn with_max_body_bytes(mut self, limit: usize) -> Self {
        self.max_body_bytes = limit;
        self
    }

    /// Override token cookie flags (Double-Submit
    /// Cookie pattern).
    ///
    /// `http_only` must be `false` for client code
    /// to read the cookie and mirror it into a
    /// header or form field.
    pub fn with_token_cookie_config(mut self, config: CsrfDoubleSubmitCookie) -> Self {
        self.token_cookie_config = Some(config);
        self
    }

    /// Set the `Secure` flag for every cookie the
    /// middleware emits (pre-session and token).
    ///
    /// Defaults to `true`. Set `false` only for local HTTP.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Set the `Domain` for every cookie the
    /// middleware emits. Use a parent like
    /// `.example.com` to share tokens across subdomains.
    ///
    /// The domain must domain-match the host serving
    /// the response, or the browser silently drops the
    /// cookie and every later request fails validation.
    ///
    /// # Security
    /// Domain-scoping shares the token with every
    /// subdomain and widens the CSRF trust boundary to
    /// all of them. Under Double-Submit Cookie the token
    /// cookie is script-readable by design, and any
    /// subdomain can read and forge it. Do not set a
    /// domain when an untrusted or user-content
    /// subdomain exists.
    ///
    /// # Migration
    /// A previous scope survives (RFC 6265 §5.3).
    /// Host-only to domain heals in-band; changing
    /// or dropping a domain strands the old cookies.
    ///
    /// `session_id_cookie_name` is yours to
    /// expire in both scopes, except at logout.
    ///
    /// # Examples
    /// ```
    /// use actix_csrf_middleware::CsrfMiddlewareConfig;
    ///
    /// let cfg = CsrfMiddlewareConfig::double_submit_cookie(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    ///     .with_cookie_domain(".example.com");
    /// ```
    pub fn with_cookie_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Skip CSRF validation for requests whose
    /// path starts with any given prefix.
    ///
    /// For health checks or public webhooks where
    /// CSRF does not apply.
    pub fn with_skip_for(mut self, patches: Vec<String>) -> Self {
        self.skip_for = patches;
        self
    }

    /// Enable strict Origin/Referer checks for
    /// mutating requests and set allowed origins.
    ///
    /// Origins are compared strictly by scheme,
    /// host, and port. If `allowed` is empty and
    /// `enforce` is `true`, all mutating requests
    /// are rejected.
    ///
    /// Example enabling one origin:
    /// ```
    /// use actix_csrf_middleware::CsrfMiddlewareConfig;
    ///
    /// let cfg = CsrfMiddlewareConfig::double_submit_cookie(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    ///     .with_enforce_origin(true, vec!["https://example.com".to_string()]);
    /// ```
    pub fn with_enforce_origin(mut self, enforce: bool, allowed: Vec<String>) -> Self {
        self.enforce_origin = enforce;
        self.allowed_origins = allowed;

        self
    }
}

/// Actix Web middleware providing CSRF protection.
///
/// Supports two patterns:
/// - Double-Submit Cookie (default): token in a
///   cookie, echoed by the client.
/// - Synchronizer Token (`actix-session`): token
///   held server-side in the session.
///
/// # How It Works
/// - Safe methods (GET/HEAD): ensures a token
///   exists and may set it in cookies. For
///   Double-Submit Cookie an anonymous
///   pre-session cookie may be issued before
///   authentication.
/// - Mutating methods (POST/PUT/PATCH/DELETE):
///   a token is required, read from the header
///   [`DEFAULT_CSRF_TOKEN_HEADER`] or the body
///   field [`DEFAULT_CSRF_TOKEN_FIELD`] (JSON or url-encoded).
///   `multipart/form-data` is rejected unless the path is
///   listed in [`CsrfMiddlewareConfig::with_multipart`].
/// - The token is rotated on successful validation.
/// - Optional Origin/Referer enforcement via
///   [`CsrfMiddlewareConfig::with_enforce_origin`].
///
/// # Examples
/// Double-Submit Cookie (no session middleware required):
/// ```
/// use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken};
/// use actix_web::{web, App, HttpResponse};
///
/// let secret = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // >= 32 bytes
/// let cfg = CsrfMiddlewareConfig::double_submit_cookie(secret);
///
/// let app = App::new()
///     .wrap(CsrfMiddleware::new(cfg))
///     .service(
///         web::resource("/form").route(web::get().to(|csrf: CsrfToken| async move {
///             HttpResponse::Ok().body(format!("token:{}", csrf.0))
///         }))
///     )
///     .service(
///         web::resource("/submit").route(web::post().to(|_csrf: CsrfToken| async move {
///             HttpResponse::Ok()
///         }))
///     );
/// ```
///
/// Synchronizer Token (requires `actix-session`) example:
/// ```ignore
/// use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig};
/// use actix_session::{storage::CookieSessionStore, SessionMiddleware};
/// use actix_web::{App, cookie::Key};
///
/// let cfg = CsrfMiddlewareConfig::synchronizer_token(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
/// let app = App::new()
///     .wrap(SessionMiddleware::new(CookieSessionStore::default(), Key::generate()))
///     .wrap(CsrfMiddleware::new(cfg));
/// ```
pub struct CsrfMiddleware {
    config: Rc<CsrfMiddlewareConfig>,
}

impl CsrfMiddleware {
    /// Creates a CSRF middleware instance
    /// with the given configuration.
    ///
    /// See [`CsrfMiddlewareConfig`] for
    /// available options and examples.
    pub fn new(config: CsrfMiddlewareConfig) -> Self {
        Self {
            config: Rc::new(config),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for CsrfMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
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
    config: Rc<CsrfMiddlewareConfig>,
}

impl<S> CsrfMiddlewareService<S> {
    fn get_session_from_cookie(
        &self,
        req: &ServiceRequest,
        state: CookieState,
    ) -> (String, bool, TokenClass) {
        if let Some(id) = req
            .cookie(&self.config.session_id_cookie_name)
            .map(|c| c.value().to_string())
        {
            (id, false, TokenClass::Authorized)
        } else if !state.dup_pre_session
            && let Some(val) = req
                .cookie(CSRF_PRE_SESSION_KEY)
                .map(|c| c.value().to_string())
        {
            if let Some(pre_id) = decode_pre_session_cookie(&val, self.config.secret_key.as_slice())
            {
                (pre_id, false, TokenClass::Anonymous)
            } else {
                (generate_random_token(), true, TokenClass::Anonymous)
            }
        } else {
            (generate_random_token(), true, TokenClass::Anonymous)
        }
    }

    fn get_true_token(
        &self,
        req: &ServiceRequest,
        session_id: Option<&str>,
        class: TokenClass,
        pre_session_regenerated: bool,
    ) -> (String, bool) {
        match self.config.pattern {
            // If corresponding feature enabled then
            // get token from persistent session storage.
            #[cfg(feature = "actix-session")]
            CsrfPattern::SynchronizerToken => {
                let session = req.get_session();
                let key = match class {
                    TokenClass::Authorized => &self.config.token_cookie_name,
                    TokenClass::Anonymous => &self.config.anon_session_key_name,
                };

                let found = session.get::<String>(key).ok().flatten();
                match found {
                    Some(tok) => (tok, false),
                    None => (generate_random_token(), true),
                }
            }
            CsrfPattern::DoubleSubmitCookie => {
                let (cookie_name, ctx) = match class {
                    TokenClass::Authorized => {
                        (&self.config.token_cookie_name, TokenClass::Authorized)
                    }
                    TokenClass::Anonymous => {
                        (&self.config.anon_token_cookie_name, TokenClass::Anonymous)
                    }
                };

                let secret = self.config.secret_key.as_slice();
                let bound_to_session = |tok: &str| {
                    session_id.is_some_and(|sid| {
                        validate_hmac_token_ctx(ctx, sid, tok.as_bytes(), secret).unwrap_or(false)
                    })
                };

                let adopted = req.cookie(cookie_name).and_then(|c| {
                    let usable = !pre_session_regenerated && bound_to_session(c.value());
                    usable.then(|| c.value().to_string())
                });

                match adopted {
                    Some(tok) => (tok, false),
                    None => {
                        let tok = generate_hmac_token_ctx(
                            ctx,
                            session_id.expect("Session or pre-session id is passed"),
                            secret,
                        );

                        (tok, true)
                    }
                }
            }
        }
    }

    fn should_skip_validation(&self, req: &ServiceRequest) -> bool {
        let req_path = req.path();
        self.config
            .skip_for
            .iter()
            .any(|prefix| req_path.starts_with(prefix))
    }

    fn scan_cookies(&self, req: &ServiceRequest) -> CookieState {
        let Ok(cookies) = req.cookies() else {
            return CookieState::default();
        };

        let (mut token, mut anon_token, mut pre_session, mut session_id) =
            (0usize, 0usize, 0usize, 0usize);

        for cookie in cookies.iter() {
            let name = cookie.name();

            if name == self.config.session_id_cookie_name {
                session_id += 1;
            } else if name == CSRF_PRE_SESSION_KEY {
                pre_session += 1;
            } else if name == self.config.token_cookie_name {
                token += 1;
            } else if name == self.config.anon_token_cookie_name {
                anon_token += 1;
            }
        }

        if session_id > 1 {
            error!(
                "session id cookie {:?} arrived {session_id} times; csrf may bind to a stale scope",
                self.config.session_id_cookie_name
            );
        }

        let double_submit = self.config.pattern == CsrfPattern::DoubleSubmitCookie;

        CookieState {
            dup_token: double_submit && token > 1,
            dup_anon_token: double_submit && anon_token > 1,
            dup_pre_session: pre_session > 1,
            has_pre_session: pre_session > 0,
            has_token: token > 0,
            has_anon_token: anon_token > 0,
            pre_session_regenerated: false,
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
    type Future = Either<CsrfTokenValidator<S, B>, Ready<Result<Self::Response, Self::Error>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if self.should_skip_validation(&req) {
            let resp = CsrfResponse {
                fut: self.service.call(req),
                config: Some(self.config.clone()),
                set_token: None,
                set_pre_session: None,
                token_class: None,
                remove_pre_session: false,
                _phantom: PhantomData,
            };

            return Either::left(CsrfTokenValidator::CsrfResponse { response: resp });
        }

        let mut state = self.scan_cookies(&req);

        // Get current token from cookie or
        // actix-session or generate new one.
        let (true_token, should_set_token, cookie_session, token_class): (
            String,
            bool,
            Option<(String, bool)>,
            Option<TokenClass>,
        ) = match self.config.pattern {
            CsrfPattern::DoubleSubmitCookie => {
                let (session_id, set_pre_session, token_class) =
                    self.get_session_from_cookie(&req, state);

                state.pre_session_regenerated = set_pre_session;

                let stale = match token_class {
                    TokenClass::Authorized => state.dup_token,
                    TokenClass::Anonymous => state.dup_anon_token,
                };

                let (true_token, should_set_token) = self.get_true_token(
                    &req,
                    Some(&session_id),
                    token_class,
                    set_pre_session || stale,
                );

                (
                    true_token,
                    should_set_token,
                    Some((session_id, set_pre_session)),
                    Some(token_class),
                )
            }
            #[cfg(feature = "actix-session")]
            CsrfPattern::SynchronizerToken => {
                // Derive class from cookies and set pre-session cookie if needed
                let (session_id, set_pre_session, token_class) =
                    self.get_session_from_cookie(&req, state);

                state.pre_session_regenerated = set_pre_session;

                let (token, should_set_token) =
                    self.get_true_token(&req, None, token_class, set_pre_session);

                (
                    token,
                    should_set_token,
                    Some((session_id, set_pre_session)),
                    Some(token_class),
                )
            }
        };

        req.extensions_mut().insert(CsrfToken(true_token.clone()));
        req.extensions_mut().insert(self.config.clone());
        req.extensions_mut().insert(state);

        let is_mutating = matches!(
            *req.method(),
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        );

        // Skip validation for read only requests, but
        // csrf token still should be added to the response
        // when should_set_token flag is set to true.
        if !is_mutating {
            let set_token_bytes = should_set_token.then_some(true_token);

            let session_id = if let Some((ref session_id, set_pre_session)) = cookie_session {
                if set_pre_session {
                    Some(session_id.clone())
                } else {
                    None
                }
            } else {
                None
            };

            let remove_pre_session = matches!(token_class, Some(TokenClass::Authorized));
            let resp = CsrfResponse {
                fut: self.service.call(req),
                config: Some(self.config.clone()),
                set_token: set_token_bytes,
                set_pre_session: session_id,
                token_class,
                remove_pre_session,
                _phantom: PhantomData,
            };

            return Either::left(CsrfTokenValidator::CsrfResponse { response: resp });
        }

        // Optionally enforce Origin/Referer before token checks
        if self.config.enforce_origin && !origin_allowed(req.headers(), &self.config) {
            let mut resp = CsrfError::OriginRejected.error_response();

            evict_host_only_twins(&mut resp, &self.config, state);

            return Either::right(ok(req
                .into_response(resp)
                .map_into_boxed_body()
                .map_into_right_body()));
        }

        // Otherwise, process mutating request with token
        // extraction from the body and future validation.

        // Handle multipart form data requests
        if let Some(ct) = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|hv| hv.to_str().ok())
            && ct.starts_with("multipart/form-data")
        {
            if !self
                .config
                .multipart_routes
                .iter()
                .any(|route| route.matches(req.path()))
            {
                let resp = CsrfError::MultipartNotAllowed.error_response();
                return Either::right(ok(req
                    .into_response(resp)
                    .map_into_boxed_body()
                    .map_into_right_body()));
            }

            // Then consumer reads body, extracts and
            // verifies csrf tokens manually in their handlers.
            let resp = CsrfResponse {
                fut: self.service.call(req),
                config: Some(self.config.clone()),
                set_token: None,
                set_pre_session: None,
                token_class: None,
                remove_pre_session: false,
                _phantom: PhantomData,
            };

            return Either::left(CsrfTokenValidator::CsrfResponse { response: resp });
        }

        let (session_id, token_class) = if let Some((session_id, _)) = cookie_session {
            (Some(session_id), token_class)
        } else {
            (None, token_class)
        };

        // Try to extract csrf token from header
        let header_token = req
            .headers()
            .get(&self.config.token_header_name)
            .and_then(|hv| hv.to_str().ok())
            .map(|s| s.to_string());

        // Fastest and easiest way when
        // token just received in headers.
        if let Some(token) = header_token {
            return Either::left(CsrfTokenValidator::MutatingRequest {
                service: self.service.clone(),
                config: self.config.clone(),
                true_token,
                client_token: token,
                session_id,
                token_class,
                req: Some(req),
            });
        }

        // For mutating requests without header token, read body first
        let mut req2 = req;
        let payload = req2.take_payload();

        // Pre-allocate body buffer using Content-Length when available and within limit
        let initial_capacity = req2
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|hv| hv.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .map(|n| n.min(self.config.max_body_bytes))
            .unwrap_or(0);

        let body_buf = if initial_capacity > 0 {
            BytesMut::with_capacity(initial_capacity)
        } else {
            BytesMut::new()
        };

        Either::left(CsrfTokenValidator::ReadingBody {
            req: Some(req2),
            payload: Some(payload),
            body_bytes: body_buf,
            config: self.config.clone(),
            service: self.service.clone(),
            true_token,
            session_id,
            token_class,
        })
    }
}

pin_project! {
    #[project = CsrfTokenValidatorProj]
    pub enum CsrfTokenValidator<S, B>
    where
        S: Service<ServiceRequest>,
        B: MessageBody,
    {
        CsrfResponse {
            #[pin]
            response: CsrfResponse<S, B>,
        },
        MutatingRequest {
            service: Rc<S>,
            config: Rc<CsrfMiddlewareConfig>,
            true_token: String,
            client_token: String,
            session_id: Option<String>,
            token_class: Option<TokenClass>,
            req: Option<ServiceRequest>
        },
        ReadingBody {
            service: Rc<S>,
            config: Rc<CsrfMiddlewareConfig>,
            req: Option<ServiceRequest>,
            payload: Option<actix_web::dev::Payload>,
            body_bytes: BytesMut,
            true_token: String,
            session_id: Option<String>,
            token_class: Option<TokenClass>,
        },
    }
}

impl<S, B> Future for CsrfTokenValidator<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
{
    type Output = Result<ServiceResponse<EitherBody<B>>, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().project() {
            CsrfTokenValidatorProj::CsrfResponse { response } => response.poll(cx),
            CsrfTokenValidatorProj::MutatingRequest {
                service,
                config,
                true_token,
                client_token,
                session_id,
                token_class,
                req,
            } => {
                #[cfg(not(feature = "actix-session"))]
                let _ = &true_token;

                match req.take() {
                    Some(req) => {
                        // Session id cannot be empty with DoubleSubmitCookie pattern
                        let session_id = if config.pattern == CsrfPattern::DoubleSubmitCookie {
                            if let Some(id) = session_id.take() {
                                Some(id)
                            } else {
                                error!("session id is empty in csrf token validator");

                                let resp = CsrfError::Internal.error_response();
                                return Poll::Ready(Ok(req
                                    .into_response(resp)
                                    .map_into_boxed_body()
                                    .map_into_right_body()));
                            }
                        } else {
                            None
                        };

                        // Validate client token based on the pattern
                        let valid = match &config.pattern {
                            #[cfg(feature = "actix-session")]
                            CsrfPattern::SynchronizerToken => {
                                if eq_tokens(true_token.as_bytes(), client_token.as_bytes()) {
                                    true
                                } else {
                                    let session = req.get_session();
                                    let alt_key = match token_class
                                        .as_ref()
                                        .copied()
                                        .unwrap_or(TokenClass::Authorized)
                                    {
                                        TokenClass::Authorized => &config.anon_session_key_name,
                                        TokenClass::Anonymous => &config.token_cookie_name,
                                    };

                                    let alt = session.get::<String>(alt_key).ok().flatten();

                                    alt.map(|t| eq_tokens(t.as_bytes(), client_token.as_bytes()))
                                        .unwrap_or(false)
                                }
                            }
                            CsrfPattern::DoubleSubmitCookie => {
                                let ctx = token_class
                                    .as_ref()
                                    .copied()
                                    .unwrap_or(TokenClass::Anonymous);

                                let Some(sid) = session_id.as_deref() else {
                                    error!("session id is empty in csrf token validator");

                                    let resp = CsrfError::Internal.error_response();
                                    return Poll::Ready(Ok(req
                                        .into_response(resp)
                                        .map_into_boxed_body()
                                        .map_into_right_body()));
                                };

                                validate_hmac_token_ctx(
                                    ctx,
                                    sid,
                                    client_token.as_bytes(),
                                    config.secret_key.as_slice(),
                                )
                                .unwrap_or(false)
                            }
                        };

                        if !valid {
                            let state = cookie_state(&req);
                            let mut resp = CsrfError::TokenInvalid.error_response();

                            evict_host_only_twins(&mut resp, config, state);

                            remint_token(
                                &mut resp,
                                config,
                                token_class.unwrap_or(TokenClass::Anonymous),
                                session_id.as_deref(),
                                state,
                            );

                            return Poll::Ready(Ok(req
                                .into_response(resp)
                                .map_into_boxed_body()
                                .map_into_right_body()));
                        }

                        // Rotate token based on configured pattern after every successful validation
                        let new_token = match &config.pattern {
                            #[cfg(feature = "actix-session")]
                            CsrfPattern::SynchronizerToken => generate_random_token(),
                            CsrfPattern::DoubleSubmitCookie => {
                                let ctx = token_class
                                    .as_ref()
                                    .copied()
                                    .unwrap_or(TokenClass::Anonymous);

                                let Some(sid) = session_id.as_deref() else {
                                    error!("session id is empty in csrf token validator");

                                    let resp = CsrfError::Internal.error_response();
                                    return Poll::Ready(Ok(req
                                        .into_response(resp)
                                        .map_into_boxed_body()
                                        .map_into_right_body()));
                                };

                                generate_hmac_token_ctx(ctx, sid, config.secret_key.as_ref())
                            }
                        };

                        let resp = CsrfResponse {
                            fut: service.call(req),
                            config: Some(config.clone()),
                            set_token: Some(new_token),
                            set_pre_session: None,
                            token_class: *token_class,
                            remove_pre_session: false,
                            _phantom: PhantomData,
                        };

                        self.set(CsrfTokenValidator::CsrfResponse { response: resp });

                        cx.waker().wake_by_ref(); // wake for the next pool
                        Poll::Pending
                    }
                    _ => {
                        error!("request already taken in csrf validator's state machine");
                        Poll::Ready(Err(CsrfError::Internal.into()))
                    }
                }
            }
            CsrfTokenValidatorProj::ReadingBody {
                service,
                config,
                req,
                payload,
                body_bytes,
                true_token,
                session_id,
                token_class,
            } => {
                if req.is_none() {
                    error!("request already taken in csrf validator's state machine");
                    return Poll::Ready(Err(CsrfError::Internal.into()));
                }

                // Safe: just checked
                let request_mut = req.as_mut().unwrap();
                let payload = match payload.as_mut() {
                    Some(p) => p,
                    None => {
                        error!("payload missing in reading body state");
                        return Poll::Ready(Err(CsrfError::Internal.into()));
                    }
                };

                match payload.poll_next_unpin(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Some(Ok(bytes))) => {
                        body_bytes.extend_from_slice(&bytes);

                        if body_bytes.len() > config.max_body_bytes {
                            let req_owned = req.take().unwrap();
                            let resp = CsrfError::BodyTooLarge.error_response();

                            return Poll::Ready(Ok(req_owned
                                .into_response(resp)
                                .map_into_boxed_body()
                                .map_into_right_body()));
                        }

                        cx.waker().wake_by_ref();

                        Poll::Pending
                    }
                    Poll::Ready(Some(Err(e))) => {
                        error!("failed to read request body for csrf extraction: {e:?}");

                        let req_owned = req.take().unwrap();
                        let resp = CsrfError::BodyRead.error_response();

                        Poll::Ready(Ok(req_owned
                            .into_response(resp)
                            .map_into_boxed_body()
                            .map_into_right_body()))
                    }
                    Poll::Ready(None) => {
                        let body = std::mem::take(&mut *body_bytes).freeze();
                        let client_token = match sync_read_token_from_body(
                            request_mut.headers(),
                            &body,
                            &config.token_form_field,
                        ) {
                            Some(token) => token,
                            None => {
                                let req_owned = req.take().unwrap();
                                let state = cookie_state(&req_owned);

                                let mut res = CsrfError::TokenMissing.error_response();

                                evict_host_only_twins(&mut res, config, state);

                                remint_token(
                                    &mut res,
                                    config,
                                    token_class.unwrap_or(TokenClass::Anonymous),
                                    session_id.as_deref(),
                                    state,
                                );

                                return Poll::Ready(Ok(req_owned
                                    .into_response(res)
                                    .map_into_boxed_body()
                                    .map_into_right_body()));
                            }
                        };

                        request_mut.set_payload(actix_web::dev::Payload::from(body.clone()));

                        let req_owned = req.take().unwrap();
                        let next_state = {
                            let service = service.clone();
                            let config = config.clone();
                            let true_token = std::mem::take(true_token);
                            let session_id = session_id.take();
                            let token_class = token_class.take();
                            let req = Some(req_owned);

                            CsrfTokenValidator::MutatingRequest {
                                service,
                                config,
                                true_token,
                                client_token,
                                session_id,
                                token_class,
                                req,
                            }
                        };

                        self.set(next_state);
                        cx.waker().wake_by_ref();

                        Poll::Pending
                    }
                }
            }
        }
    }
}

pin_project! {
    pub struct CsrfResponse<S, B>
    where
        S: Service<ServiceRequest>,
        B: MessageBody,
    {
        #[pin]
        fut: S::Future,
        config: Option<Rc<CsrfMiddlewareConfig>>,
        set_token: Option<String>,
        set_pre_session: Option<String>,
        token_class: Option<TokenClass>,
        remove_pre_session: bool,
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
        match ready!(this.fut.poll(cx)) {
            Ok(mut resp) => {
                let config = match &this.config {
                    Some(config) => config,
                    None => {
                        error!("unable to extract csrf middleware config in csrf response");

                        let res = CsrfError::Internal.error_response();
                        return Poll::Ready(Ok(resp
                            .into_response(res)
                            .map_into_boxed_body()
                            .map_into_right_body()));
                    }
                };

                let state = cookie_state(resp.request());
                evict_host_only_twins(resp.response_mut(), config, state);

                // Set pre-session if requested
                if let Some(pre_session_id) = this.set_pre_session {
                    let cookie_val =
                        encode_pre_session_cookie(pre_session_id, config.secret_key.as_slice());

                    let mut pre_session_cookie = Cookie::build(CSRF_PRE_SESSION_KEY, cookie_val)
                        .http_only(PRE_SESSION_HTTP_ONLY)
                        .secure(config.secure)
                        .same_site(PRE_SESSION_SAME_SITE)
                        .path("/")
                        .finish();

                    apply_domain(&mut pre_session_cookie, config.domain.as_deref());

                    match resp.response_mut().add_cookie(&pre_session_cookie) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("unable to set pre-session cookie in csrf response: {e:?}");

                            let res = CsrfError::Internal.error_response();
                            return Poll::Ready(Ok(resp
                                .into_response(res)
                                .map_into_boxed_body()
                                .map_into_right_body()));
                        }
                    }
                }

                if *this.remove_pre_session {
                    if state.has_pre_session
                        && let Err(e) = resp.response_mut().add_cookie(&expired_pre_session_cookie(
                            config.secure,
                            config.domain.as_deref(),
                        ))
                    {
                        error!("unable to expire pre-session cookie in csrf response: {e:?}");

                        let res = CsrfError::Internal.error_response();
                        return Poll::Ready(Ok(resp
                            .into_response(res)
                            .map_into_boxed_body()
                            .map_into_right_body()));
                    }

                    // Expire anonymous token cookie
                    if state.has_anon_token
                        && matches!(config.pattern, CsrfPattern::DoubleSubmitCookie)
                        && let Err(e) = resp.response_mut().add_cookie(&expire_cookie(
                            &config.anon_token_cookie_name,
                            config.secure,
                            config.domain.as_deref(),
                        ))
                    {
                        error!("unable to expire anon token cookie in csrf response: {e:?}");

                        let res = CsrfError::Internal.error_response();
                        return Poll::Ready(Ok(resp
                            .into_response(res)
                            .map_into_boxed_body()
                            .map_into_right_body()));
                    }
                }

                // On logout teardown the handler already expired
                // the token cookies; a refresh here would re-issue
                // them via a later Set-Cookie and undo it.
                let teardown = resp.request().extensions().get::<CsrfTeardown>().is_some();

                if let Some(new_token) = this.set_token.take().filter(|_| !teardown) {
                    match config.pattern {
                        #[cfg(feature = "actix-session")]
                        CsrfPattern::SynchronizerToken => {
                            if *this.remove_pre_session {
                                let _ = resp
                                    .request()
                                    .get_session()
                                    .remove(&config.anon_session_key_name);
                            }

                            // Set a new token into actix session under key decided by class
                            let key = match this.token_class.unwrap_or(TokenClass::Authorized) {
                                TokenClass::Authorized => &config.token_cookie_name,
                                TokenClass::Anonymous => &config.anon_session_key_name,
                            };

                            match resp.request().get_session().insert(key, new_token) {
                                Ok(()) => {}
                                Err(e) => {
                                    error!(
                                        "unable to set a csrf token with actix session in csrf response: {e:?}"
                                    );

                                    let res = CsrfError::Internal.error_response();
                                    return Poll::Ready(Ok(resp
                                        .into_response(res)
                                        .map_into_boxed_body()
                                        .map_into_right_body()));
                                }
                            }
                        }
                        CsrfPattern::DoubleSubmitCookie => {
                            let cookie_config = match &config.token_cookie_config {
                                Some(config) => config,
                                None => {
                                    error!(
                                        "unable to extract token_cookie_config in csrf response"
                                    );

                                    let res = CsrfError::Internal.error_response();
                                    return Poll::Ready(Ok(resp
                                        .into_response(res)
                                        .map_into_boxed_body()
                                        .map_into_right_body()));
                                }
                            };

                            // Choose cookie name based on token class
                            let cookie_name =
                                match this.token_class.unwrap_or(TokenClass::Anonymous) {
                                    TokenClass::Authorized => &config.token_cookie_name,
                                    TokenClass::Anonymous => &config.anon_token_cookie_name,
                                };

                            let mut new_token_cookie = Cookie::build(cookie_name, new_token)
                                .http_only(cookie_config.http_only)
                                .secure(config.secure)
                                .same_site(cookie_config.same_site)
                                .path("/")
                                .finish();

                            apply_domain(&mut new_token_cookie, config.domain.as_deref());

                            // Update token cookie with a new token
                            match resp.response_mut().add_cookie(&new_token_cookie) {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("unable to set a token cookie in csrf response: {e:?}");

                                    let res = CsrfError::Internal.error_response();
                                    return Poll::Ready(Ok(resp
                                        .into_response(res)
                                        .map_into_boxed_body()
                                        .map_into_right_body()));
                                }
                            }
                        }
                    }
                }

                Poll::Ready(Ok(resp.map_into_left_body()))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl CsrfRequestExt for HttpRequest {
    fn rotate_csrf_after_login(
        &self,
        session_id: &str,
        resp: &mut HttpResponseBuilder,
    ) -> Result<(), Error> {
        let config = config_from_request(self)?;
        rotate_csrf_after_login(session_id, self, resp, config.as_ref())
    }

    fn rotate_csrf_after_logout(&self, resp: &mut HttpResponseBuilder) -> Result<(), Error> {
        let config = config_from_request(self)?;
        rotate_csrf_after_logout(self, resp, config.as_ref())
    }
}

/// Generates a cryptographically secure random CSRF token.
///
/// 32 random bytes, base64url-encoded without
/// padding (43 ASCII chars from `A-Z`, `a-z`,
/// `0-9`, `-`, `_`), safe in URLs, HTTP headers,
/// and HTML form fields without escaping.
///
/// A standalone random value, not bound to any
/// session or identity. For the Double-Submit
/// Cookie pattern prefer [`generate_hmac_token_ctx`],
/// which derives an HMAC-protected, unforgeable
/// token from a session id.
///
/// # Security
/// - Generated with a CSPRNG.
/// - Double-Submit Cookie: do not put this raw
///   token in a cookie alone; [`generate_hmac_token_ctx`]
///   yields a token the server can verify.
/// - Synchronizer Token (`actix-session`): may be
///   stored server-side and compared in constant time.
///
/// # Examples
/// Generate a token and validate its shape.
/// ```
/// let tok = actix_csrf_middleware::generate_random_token();
/// assert_eq!(tok.len(), 43, "32 bytes base64url-encoded -> 43 chars");
/// assert!(tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
/// ```
///
/// Produce an HMAC-protected token for Double-Submit Cookie flows.
/// ```
/// use actix_csrf_middleware::{generate_random_token, generate_hmac_token_ctx, TokenClass};
///
/// let session_id = "user-session-id";
/// let secret = b"an-application-wide-secret-at-least-32-bytes-long";
/// let raw = generate_random_token();
///
/// // In typical flows you would call `generate_hmac_token_ctx` directly without
/// // generating the raw token yourself; shown here for illustration.
/// let hmac_token = generate_hmac_token_ctx(TokenClass::Authorized, session_id, secret);
/// assert!(hmac_token.contains('.'));
///
/// let parts: Vec<_> = hmac_token.split('.').collect();
/// assert_eq!(parts.len(), 2);
/// ```
pub fn generate_random_token() -> String {
    let mut buf = [0u8; TOKEN_LEN];
    rand::rng().fill_bytes(&mut buf);

    URL_SAFE_NO_PAD.encode(buf)
}

/// Generates an HMAC-protected CSRF token bound to a context and identifier.
///
/// Token shape is `HEX_HMAC.RANDOM`:
/// - `RANDOM`: fresh value from [`generate_random_token`].
/// - `HEX_HMAC`: hex-encoded HMAC-SHA256 over
///   `"{class}|{id}|{RANDOM}"` with `secret`.
///
/// For the Double-Submit Cookie pattern: the server
/// sets the token as a cookie and expects the client
/// to echo it via a form field or header. On receipt
/// it recomputes the HMAC with the same `class`, `id`,
/// and `secret`; a match proves the token authentic
/// and unforgeable by the client.
///
/// `class` selects the logical bucket:
/// - Authorized: bound to an authenticated
///   session ([`TokenClass::Authorized`]).
/// - Anonymous: pre-session, used before
///   authentication ([`TokenClass::Anonymous`]).
///
/// # Parameters
/// - `class`: token namespace (authorized vs anonymous).
/// - `id`: identifier bound into the token (e.g. a
///   session id); must match at verification.
/// - `secret`: application-wide key (>= 32 bytes).
///   Changing it invalidates all tokens at once.
///
/// # Security
/// - Unforgeable without `secret` and `id`.
/// - Distinct `class` values keep anonymous and
///   authorized tokens non-interchangeable.
/// - Use a high-entropy `secret` of >= 32 bytes.
///
/// # Examples
/// Generate and verify an authorized token.
/// ```
/// use actix_csrf_middleware::{generate_hmac_token_ctx, validate_hmac_token_ctx, TokenClass};
///
/// let session_id = "user-session-id";
/// let secret = b"an-application-wide-secret-at-least-32-bytes!";
/// let tok = generate_hmac_token_ctx(TokenClass::Authorized, session_id, secret);
///
/// assert!(tok.contains('.'));
/// assert!(validate_hmac_token_ctx(TokenClass::Authorized, session_id, tok.as_bytes(), secret).unwrap());
/// ```
///
/// Generate an anonymous token (pre-session) and verify it with the same `id` and `class`.
/// ```
/// use actix_csrf_middleware::{generate_hmac_token_ctx, validate_hmac_token_ctx, TokenClass};
///
/// let pre_session_id = "pre-session";
/// let secret = b"an-application-wide-secret-at-least-32-bytes!";
/// let tok = generate_hmac_token_ctx(TokenClass::Anonymous, pre_session_id, secret);
///
/// assert!(validate_hmac_token_ctx(TokenClass::Anonymous, pre_session_id, tok.as_bytes(), secret).unwrap());
/// ```
pub fn generate_hmac_token_ctx(class: TokenClass, id: &str, secret: &[u8]) -> String {
    let mut raw = [0u8; TOKEN_LEN];
    rand::rng().fill_bytes(&mut raw);

    let mut b64 = [0u8; TOKEN_B64_LEN];
    URL_SAFE_NO_PAD
        .encode_slice(raw, &mut b64)
        .expect("TOKEN_B64_LEN is derived from TOKEN_LEN");

    let tok = std::str::from_utf8(&b64).expect("base64url output is ascii");

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(class.as_str().as_bytes());
    mac.update(b"|");
    mac.update(id.as_bytes());
    mac.update(b"|");
    mac.update(tok.as_bytes());

    join_token(&mac.finalize().into_bytes(), tok)
}

/// Constant-time equality for token byte slices.
///
/// Timing-attack resistant, leaking nothing
/// about token values. Prefer the higher-level
/// helpers for CSRF validation; this is useful
/// when comparing raw secrets or signatures.
///
/// # Examples
/// ```
/// use actix_csrf_middleware::eq_tokens;
/// assert!(eq_tokens(b"abc", b"abc"));
/// assert!(!eq_tokens(b"abc", b"abcd"));
/// ```
pub fn eq_tokens(token_a: &[u8], token_b: &[u8]) -> bool {
    token_a.ct_eq(token_b).unwrap_u8() == 1
}

/// Upgrade anonymous CSRF state to authorized
/// and write the cookie updates to `resp`.
///
/// Call after a successful login or privilege
/// escalation, once the session id cookie is set.
/// Expires the pre-session marker, then:
/// - Double-Submit Cookie: sets a fresh HMAC
///   authorized token cookie bound to `session_id`
///   and expires any anonymous token cookie.
/// - Synchronizer Token: stores a fresh random
///   authorized token in the session and removes
///   the anonymous token.
///
/// # Errors
/// `InternalServerError` if the session
/// update fails (Synchronizer Token).
#[cfg_attr(not(feature = "actix-session"), allow(unused_variables))]
pub fn rotate_csrf_after_login(
    session_id: &str,
    req: &HttpRequest,
    resp: &mut HttpResponseBuilder,
    config: &CsrfMiddlewareConfig,
) -> Result<(), Error> {
    resp.cookie(expired_pre_session_cookie(
        config.secure,
        config.domain.as_deref(),
    ));

    match config.pattern {
        #[cfg(feature = "actix-session")]
        CsrfPattern::SynchronizerToken => {
            let session = req.get_session();
            let _ = session.remove(&config.anon_session_key_name);

            session
                .insert(&config.token_cookie_name, generate_random_token())
                .map_err(|_| {
                    actix_web::error::ErrorInternalServerError(
                        "Failed to rotate CSRF token in session",
                    )
                })?;

            Ok(())
        }
        CsrfPattern::DoubleSubmitCookie => {
            let token = generate_hmac_token_ctx(
                TokenClass::Authorized,
                session_id,
                config.secret_key.as_slice(),
            );

            let (http_only, same_site) = match &config.token_cookie_config {
                Some(cfg) => (cfg.http_only, cfg.same_site),
                None => (true, SameSite::Lax),
            };

            let mut csrf_cookie = Cookie::build(&config.token_cookie_name, token)
                .http_only(http_only)
                .secure(config.secure)
                .same_site(same_site)
                .path("/")
                .finish();

            apply_domain(&mut csrf_cookie, config.domain.as_deref());

            resp.cookie(csrf_cookie);
            resp.cookie(expire_cookie(
                &config.anon_token_cookie_name,
                config.secure,
                config.domain.as_deref(),
            ));

            Ok(())
        }
    }
}

/// Tear down authorized CSRF state and write
/// the cookie updates to `resp`.
///
/// Call on logout. Expires the pre-session marker
/// and marks the request for the middleware to skip
/// its post-mutation token refresh, which would
/// otherwise re-issue the authorized cookie this
/// just expired. Then, per pattern:
/// - Double-Submit Cookie: expires the session id cookie
///   and the authorized and anonymous token cookies.
/// - Synchronizer Token: purges the server-side
///   session (clearing the authorized and anonymous
///   tokens and expiring the session cookie via `actix-session`).
///
/// The next anonymous request re-mints a fresh
/// pre-session / anonymous token pair. Unlike
/// [`rotate_csrf_after_login`], this takes no
/// `session_id`: logout ends the session rather
/// than binding a new token to it.
///
/// # Errors
/// Infallible in practice; returns `Result` for
/// signature symmetry with [`rotate_csrf_after_login`].
#[cfg_attr(not(feature = "actix-session"), allow(unused_variables))]
pub fn rotate_csrf_after_logout(
    req: &HttpRequest,
    resp: &mut HttpResponseBuilder,
    config: &CsrfMiddlewareConfig,
) -> Result<(), Error> {
    req.extensions_mut().insert(CsrfTeardown);

    resp.cookie(expired_pre_session_cookie(
        config.secure,
        config.domain.as_deref(),
    ));

    match config.pattern {
        #[cfg(feature = "actix-session")]
        CsrfPattern::SynchronizerToken => {
            req.get_session().purge();
        }
        CsrfPattern::DoubleSubmitCookie => {
            resp.cookie(expire_cookie(
                &config.session_id_cookie_name,
                config.secure,
                config.domain.as_deref(),
            ));
            resp.cookie(expire_cookie(
                &config.token_cookie_name,
                config.secure,
                config.domain.as_deref(),
            ));
            resp.cookie(expire_cookie(
                &config.anon_token_cookie_name,
                config.secure,
                config.domain.as_deref(),
            ));

            if config.domain.is_some() {
                resp.cookie(expire_cookie(
                    &config.session_id_cookie_name,
                    config.secure,
                    None,
                ));
                resp.cookie(expire_cookie(
                    &config.token_cookie_name,
                    config.secure,
                    None,
                ));
                resp.cookie(expire_cookie(
                    &config.anon_token_cookie_name,
                    config.secure,
                    None,
                ));
                resp.cookie(expired_pre_session_cookie(config.secure, None));
            }
        }
    }

    Ok(())
}

/// Verifies an HMAC-protected CSRF token
/// for a given class and identifier.
///
/// Accepts the `HEX_HMAC.RANDOM` format from
/// [`generate_hmac_token_ctx`]. `Ok(true)` on a
/// valid token, `Ok(false)` on structural or
/// verification failure, `Err` only on malformed
/// UTF-8 or hex while parsing.
///
/// The HMAC-SHA256 over `"{class}|{id}|{RANDOM}"`
/// is recomputed with `secret` and compared in
/// constant time.
///
/// # Errors
/// - Returns `Err` if `token` is not valid UTF-8.
/// - Returns `Err` if the HMAC hex part cannot be decoded.
///
/// # Examples
/// ```
/// use actix_csrf_middleware::{
///     generate_hmac_token_ctx, validate_hmac_token_ctx, TokenClass
/// };
///
/// let sid = "SID-xyz";
/// let secret = b"application-secret-at-least-32-bytes-long";
/// let token = generate_hmac_token_ctx(TokenClass::Authorized, sid, secret);
///
/// assert!(validate_hmac_token_ctx(TokenClass::Authorized, sid, token.as_bytes(), secret).unwrap());
///
/// // Wrong class or id will fail verification
/// assert!(!validate_hmac_token_ctx(TokenClass::Anonymous, sid, token.as_bytes(), secret).unwrap());
/// assert!(!validate_hmac_token_ctx(TokenClass::Authorized, "SID-other", token.as_bytes(), secret).unwrap());
/// ```
pub fn validate_hmac_token_ctx(
    class: TokenClass,
    id: &str,
    token: &[u8],
    secret: &[u8],
) -> Result<bool, Error> {
    let token_str = std::str::from_utf8(token)?;
    let parts: Vec<&str> = token_str.split('.').collect();

    if parts.len() != 2 {
        return Ok(false);
    }

    let (hmac_hex, csrf_token) = (parts[0], parts[1]);
    let hmac_bytes = hex::decode(hmac_hex).map_err(actix_web::error::ErrorInternalServerError)?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(actix_web::error::ErrorInternalServerError)?;
    mac.update(class.as_str().as_bytes());
    mac.update(b"|");
    mac.update(id.as_bytes());
    mac.update(b"|");
    mac.update(csrf_token.as_bytes());

    let expected_hmac = mac.finalize().into_bytes();

    Ok(eq_tokens(&expected_hmac, &hmac_bytes))
}

/// Validate an authorized-class CSRF token.
///
/// [`validate_hmac_token_ctx`] fixed to
/// [`TokenClass::Authorized`], for tests and
/// simple flows that only expect authorized tokens.
///
/// # Examples
/// ```
/// use actix_csrf_middleware::{
///     generate_hmac_token_ctx, validate_hmac_token, TokenClass
/// };
///
/// let sid = "SID-xyz";
/// let secret = b"application-secret-at-least-32-bytes-long";
/// let token = generate_hmac_token_ctx(TokenClass::Authorized, sid, secret);
///
/// assert!(validate_hmac_token(sid, token.as_bytes(), secret).unwrap());
/// ```
pub fn validate_hmac_token(session_id: &str, token: &[u8], secret: &[u8]) -> Result<bool, Error> {
    validate_hmac_token_ctx(TokenClass::Authorized, session_id, token, secret)
}

fn sync_read_token_from_body(
    headers: &HeaderMap,
    body: &[u8],
    token_field: &str,
) -> Option<String> {
    if let Some(ct) = headers.get(header::CONTENT_TYPE)
        && let Ok(ct) = ct.to_str()
    {
        if ct.starts_with("application/json") {
            let mut de = serde_json::Deserializer::from_slice(body);

            let found = TokenFromMap(token_field).deserialize(&mut de).ok()?;
            de.end().ok()?;

            return found;
        } else if ct.starts_with("application/x-www-form-urlencoded") {
            let mut found = None;
            for (key, value) in url::form_urlencoded::parse(body) {
                if key == token_field {
                    found = Some(value.into_owned());
                }
            }

            return found;
        } else {
            warn!("unsupported request content type, unable to extract and verify csrf token");
        }
    }
    None
}

fn config_from_request(req: &HttpRequest) -> Result<Rc<CsrfMiddlewareConfig>, Error> {
    req.extensions()
        .get::<Rc<CsrfMiddlewareConfig>>()
        .cloned()
        .ok_or_else(|| {
            error!("CSRF middleware config not found in request extensions");
            CsrfError::Internal.into()
        })
}

fn join_token(digest: &[u8], body: &str) -> String {
    let mut out = String::with_capacity(digest.len() * 2 + 1 + body.len());
    for &b in digest {
        out.push(HEX_DIGITS[usize::from(b >> 4)] as char);
        out.push(HEX_DIGITS[usize::from(b & 0x0f)] as char);
    }

    out.push('.');
    out.push_str(body);

    out
}

fn encode_pre_session_cookie(id: &str, secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(b"pre|");
    mac.update(id.as_bytes());

    join_token(&mac.finalize().into_bytes(), id)
}

fn decode_pre_session_cookie(val: &str, secret: &[u8]) -> Option<String> {
    let parts: Vec<&str> = val.split('.').collect();
    if parts.len() != 2 {
        return None;
    }

    let (sig_hex, id) = (parts[0], parts[1]);
    let sig_bytes = hex::decode(sig_hex).ok()?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).ok()?;
    mac.update(b"pre|");
    mac.update(id.as_bytes());

    let expected = mac.finalize().into_bytes();

    if eq_tokens(&expected, &sig_bytes) {
        Some(id.to_string())
    } else {
        None
    }
}

fn expire_cookie(name: &str, secure: bool, domain: Option<&str>) -> Cookie<'static> {
    let mut del = Cookie::new(name.to_owned(), "");
    del.set_max_age(time::Duration::seconds(0));
    del.set_expires(time::OffsetDateTime::UNIX_EPOCH);
    del.set_path("/");
    del.set_secure(secure);

    apply_domain(&mut del, domain);

    del
}

fn expired_pre_session_cookie(secure: bool, domain: Option<&str>) -> Cookie<'static> {
    let mut del = expire_cookie(CSRF_PRE_SESSION_KEY, secure, domain);
    del.set_http_only(PRE_SESSION_HTTP_ONLY);
    del.set_same_site(PRE_SESSION_SAME_SITE);

    del
}

fn apply_domain(cookie: &mut Cookie<'_>, domain: Option<&str>) {
    if let Some(d) = domain {
        cookie.set_domain(d.to_owned());
    }
}

fn cookie_state<M: HttpMessage>(req: &M) -> CookieState {
    req.extensions()
        .get::<CookieState>()
        .copied()
        .unwrap_or_default()
}

/// RFC 6265 §5.3 keys the jar on
/// name, domain and path together.
fn evict_host_only_twins<B>(
    resp: &mut HttpResponse<B>,
    config: &CsrfMiddlewareConfig,
    state: CookieState,
) {
    if config.domain.is_none() || !state.any_duplicate() {
        return;
    }

    let mut evict = |cookie: Cookie<'static>| {
        if let Err(e) = resp.add_cookie(&cookie) {
            error!("unable to evict host-only csrf cookie twin: {e:?}");
        }
    };

    if state.dup_token {
        evict(expire_cookie(
            &config.token_cookie_name,
            config.secure,
            None,
        ));
    }

    if state.dup_anon_token {
        evict(expire_cookie(
            &config.anon_token_cookie_name,
            config.secure,
            None,
        ));
    }

    if state.dup_pre_session {
        evict(expired_pre_session_cookie(config.secure, None));
    }
}

fn remint_token<B>(
    resp: &mut HttpResponse<B>,
    config: &CsrfMiddlewareConfig,
    class: TokenClass,
    session_id: Option<&str>,
    state: CookieState,
) {
    if config.pattern != CsrfPattern::DoubleSubmitCookie {
        return;
    }

    let identity_outlives_response = !state.pre_session_regenerated;
    let client_holds_class_token = match class {
        TokenClass::Authorized => state.has_token,
        TokenClass::Anonymous => state.has_anon_token,
    };

    if !identity_outlives_response || !client_holds_class_token {
        return;
    }

    let Some(sid) = session_id else {
        return;
    };

    let name = match class {
        TokenClass::Authorized => &config.token_cookie_name,
        TokenClass::Anonymous => &config.anon_token_cookie_name,
    };

    let (http_only, same_site) = match &config.token_cookie_config {
        Some(cfg) => (cfg.http_only, cfg.same_site),
        None => (true, SameSite::Lax),
    };

    let token = generate_hmac_token_ctx(class, sid, config.secret_key.as_slice());

    let mut cookie = Cookie::build(name.clone(), token)
        .http_only(http_only)
        .secure(config.secure)
        .same_site(same_site)
        .path("/")
        .finish();

    apply_domain(&mut cookie, config.domain.as_deref());

    if let Err(e) = resp.add_cookie(&cookie) {
        error!("unable to remint csrf token on a rejected request: {e:?}");
    }
}

fn check_secret_key(secret_key: &[u8]) {
    if secret_key.len() < 32 {
        panic!("csrf secret_key too short: require >=32 bytes");
    }
}

fn check_multipart_route(route: &MultipartRoute) {
    let path = route.path();

    if !path.starts_with('/') || path.contains(['?', '#']) {
        panic!("csrf multipart route {path:?} never matches a request path");
    }

    if matches!(route, MultipartRoute::Prefix(_)) && path.trim_end_matches('/').is_empty() {
        panic!("csrf multipart prefix {path:?} exempts every path");
    }
}

fn origin_allowed(headers: &HeaderMap, cfg: &CsrfMiddlewareConfig) -> bool {
    if !cfg.enforce_origin {
        return true;
    }

    if cfg.allowed_origins.is_empty() {
        return false;
    }

    // Helper to compare origins strictly (scheme, host, port)
    let is_allowed_origin = |u: &Url| -> bool {
        cfg.allowed_origins.iter().any(|allowed| {
            if let Ok(au) = Url::parse(allowed) {
                au.scheme() == u.scheme()
                    && au.host_str() == u.host_str()
                    && au.port_or_known_default() == u.port_or_known_default()
            } else {
                false
            }
        })
    };

    // Try Origin header first (preferred)
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|hv| hv.to_str().ok()) {
        if let Ok(u) = Url::parse(origin) {
            return is_allowed_origin(&u);
        }

        return false;
    }

    // Fallback:
    // Referer header, use its origin
    if let Some(referer) = headers.get(header::REFERER).and_then(|hv| hv.to_str().ok()) {
        if let Ok(u) = Url::parse(referer) {
            let origin = format!(
                "{}://{}{}",
                u.scheme(),
                u.host_str().unwrap_or(""),
                u.port().map(|p| format!(":{p}")).unwrap_or_default()
            );

            if let Ok(o) = Url::parse(&origin) {
                return is_allowed_origin(&o);
            }
        }

        return false;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::MultipartRoute;

    #[test]
    fn exact_matches_only_itself() {
        let route = MultipartRoute::Exact("/upload".to_owned());

        assert!(route.matches("/upload"));
        assert!(!route.matches("/upload/"));
        assert!(!route.matches("/upload/1"));
        assert!(!route.matches("/uploads"));
    }

    #[test]
    fn prefix_stops_at_segment_boundary() {
        let route = MultipartRoute::Prefix("/files".to_owned());

        assert!(route.matches("/files"));
        assert!(route.matches("/files/1/raw"));
        assert!(!route.matches("/filesystem"));
        assert!(!route.matches("/files-admin"));
    }

    #[test]
    fn prefix_ignores_configured_trailing_slash() {
        let bare = MultipartRoute::Prefix("/files".to_owned());
        let slashed = MultipartRoute::Prefix("/files/".to_owned());

        for path in ["/files", "/files/1", "/filesystem"] {
            assert_eq!(bare.matches(path), slashed.matches(path), "{path}");
        }
    }
}
