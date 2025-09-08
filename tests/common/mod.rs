use actix_csrf_middleware::{
    CsrfMiddleware, CsrfMiddlewareConfig, CsrfPattern, CsrfToken, CSRF_PRE_SESSION_KEY,
    DEFAULT_CSRF_ANON_TOKEN_KEY, DEFAULT_CSRF_TOKEN_KEY, DEFAULT_SESSION_ID_KEY,
};
use actix_http::body::{BoxBody, EitherBody};
use actix_http::Request;
#[cfg(feature = "actix-session")]
use actix_session::{
    config::CookieContentSecurity, storage::CookieSessionStore, SessionMiddleware,
};
use actix_web::cookie::{Cookie, Key, SameSite};
use actix_web::dev::{Service, ServiceResponse};
use actix_web::{test, web, App, HttpResponse};
use hmac::Hmac;
use sha2::Sha256;

#[allow(dead_code)]
pub type HmacSha256 = Hmac<Sha256>;

#[allow(dead_code)]
pub const HMAC_SECRET: &[u8] = b"secret-key";

pub fn test_key() -> Key {
    Key::generate()
}

pub async fn build_app(
    cfg: CsrfMiddlewareConfig,
) -> impl Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>
{
    test::init_service({
        let app = App::new().wrap(CsrfMiddleware::new(cfg));
        #[cfg(feature = "actix-session")]
        let app = app.wrap(get_session_middleware());
        app.configure(configure_routes)
    })
    .await
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/form",
        web::get().to(|csrf: CsrfToken| async move {
            HttpResponse::Ok().body(format!("token:{}", csrf.0))
        }),
    )
    .route(
        "/submit",
        web::post().to(|_csrf: CsrfToken| async move { HttpResponse::Ok().body("OK") }),
    )
    .route(
        "/submit_get",
        web::get().to(|| async move { HttpResponse::Ok().body("GET_OK") }),
    );
}

#[cfg(feature = "actix-session")]
fn get_session_middleware() -> SessionMiddleware<CookieSessionStore> {
    SessionMiddleware::builder(CookieSessionStore::default(), test_key())
        .cookie_content_security(CookieContentSecurity::Private)
        .cookie_secure(false) // Set to false for testing (no HTTPS in tests)
        .cookie_http_only(true)
        .cookie_same_site(SameSite::Lax) // Lax instead of Strict for testing
        .build()
}

#[allow(dead_code)]
pub fn config_for_with_secret(pattern: CsrfPattern, secret_key: &[u8]) -> CsrfMiddlewareConfig {
    match pattern {
        #[cfg(feature = "actix-session")]
        CsrfPattern::SynchronizerToken => CsrfMiddlewareConfig::synchronizer_token(secret_key),
        CsrfPattern::DoubleSubmitCookie => CsrfMiddlewareConfig::double_submit_cookie(secret_key),
    }
}

#[allow(dead_code)]
pub async fn token_and_cookies_for<S>(
    app: &S,
    pattern: &CsrfPattern,
) -> (String, Vec<Cookie<'static>>)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    match pattern {
        CsrfPattern::DoubleSubmitCookie => {
            let req = test::TestRequest::get().uri("/form").to_request();
            let resp = test::call_service(&app, req).await;

            let token_cookie = resp
                .response()
                .cookies()
                .find(|c| {
                    c.name() == DEFAULT_CSRF_TOKEN_KEY || c.name() == DEFAULT_CSRF_ANON_TOKEN_KEY
                })
                .map(|c| c.into_owned())
                .expect("token cookie present");

            let session_cookie = resp
                .response()
                .cookies()
                .find(|c| c.name() == DEFAULT_SESSION_ID_KEY || c.name() == CSRF_PRE_SESSION_KEY)
                .map(|c| c.into_owned())
                .expect("session/pre-session cookie present");

            let body = test::read_body(resp).await;
            let token = String::from_utf8(body.to_vec()).unwrap();
            let token = token.strip_prefix("token:").unwrap().to_string();

            (token, vec![token_cookie, session_cookie])
        }
        #[cfg(feature = "actix-session")]
        CsrfPattern::SynchronizerToken => {
            // First GET: obtain session cookie (anon)
            let req1 = test::TestRequest::get().uri("/form").to_request();
            let resp1 = test::call_service(&app, req1).await;
            let session_cookie = resp1
                .response()
                .cookies()
                .find(|c| c.name() == DEFAULT_SESSION_ID_KEY)
                .map(|c| c.into_owned())
                .expect("session cookie present");

            // Second GET with session cookie: obtain authorized token
            let req2 = test::TestRequest::get()
                .uri("/form")
                .cookie(session_cookie.clone())
                .to_request();
            let resp2 = test::call_service(&app, req2).await;
            let session_cookie2 = resp2
                .response()
                .cookies()
                .find(|c| c.name() == DEFAULT_SESSION_ID_KEY)
                .map(|c| c.into_owned())
                .unwrap_or_else(|| session_cookie.clone());

            let body2 = test::read_body(resp2).await;
            let token2 = String::from_utf8(body2.to_vec()).unwrap();
            let token2 = token2.strip_prefix("token:").unwrap().to_string();

            (token2, vec![session_cookie2])
        }
    }
}

// Macro to generate tests for both CSRF patterns
#[allow(unused_macros)]
macro_rules! for_patterns {
    ($name_double:ident, $name_sync:ident, $body:expr) => {
        #[actix_web::test]
        async fn $name_double() {
            let cfg = common::config_for_with_secret(
                actix_csrf_middleware::CsrfPattern::DoubleSubmitCookie,
                &get_secret_key(),
            );
            let app = common::build_app(cfg).await;

            $body(actix_csrf_middleware::CsrfPattern::DoubleSubmitCookie, &app).await;
        }

        #[cfg(feature = "actix-session")]
        #[actix_web::test]
        async fn $name_sync() {
            let cfg = common::config_for_with_secret(
                actix_csrf_middleware::CsrfPattern::SynchronizerToken,
                &get_secret_key(),
            );
            let app = common::build_app(cfg).await;

            $body(actix_csrf_middleware::CsrfPattern::SynchronizerToken, &app).await;
        }
    };
}
