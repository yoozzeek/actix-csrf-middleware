#[macro_use]
mod common;

use actix_csrf_middleware::{
    CsrfMiddleware, CsrfMiddlewareConfig, CsrfRequestExt, CSRF_PRE_SESSION_KEY,
    DEFAULT_CSRF_TOKEN_HEADER, DEFAULT_CSRF_TOKEN_KEY, DEFAULT_SESSION_ID_KEY,
};
use actix_http::body::{BoxBody, EitherBody};
use actix_http::Request;
#[cfg(feature = "actix-session")]
use actix_session::{
    config::CookieContentSecurity, storage::CookieSessionStore, SessionMiddleware,
};
use actix_web::cookie::{time, Cookie};
#[cfg(feature = "actix-session")]
use actix_web::cookie::{Key, SameSite};
use actix_web::dev::{Service, ServiceResponse};
use actix_web::{http::StatusCode, test, web, App, HttpRequest, HttpResponse};

// Build app with CsrfMiddleware and an extra "/auth" route that calls the extension helper
async fn build_app_with_auth(
    cfg: CsrfMiddlewareConfig,
) -> impl Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>
{
    test::init_service({
        let app = App::new().wrap(CsrfMiddleware::new(cfg));
        #[cfg(feature = "actix-session")]
        let app = app.wrap(
            SessionMiddleware::builder(CookieSessionStore::default(), Key::generate())
                .cookie_content_security(CookieContentSecurity::Private)
                .cookie_name(DEFAULT_SESSION_ID_KEY.to_string())
                .cookie_secure(false)
                .cookie_http_only(true)
                .cookie_same_site(SameSite::Lax)
                .build(),
        );
        app.configure(common::configure_routes).service(
            web::resource("/auth")
                .route(web::get().to(auth_handler))
                .route(web::post().to(auth_handler)),
        )
    })
    .await
}

async fn auth_handler(req: HttpRequest) -> actix_web::Result<HttpResponse> {
    let mut resp = HttpResponse::Ok();
    req.rotate_csrf_token_in_response(&mut resp)?;
    Ok(resp.finish())
}

fn get_secret_key() -> Vec<u8> {
    b"ext-secret-ext-secret-ext-secret-123456".to_vec()
}

#[actix_web::test]
async fn rotates_token_via_request_ext_double_submit_cookie() {
    // Build app with DoubleSubmitCookie pattern
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key());
    let app = build_app_with_auth(cfg).await;

    // Prepare a session id cookie and obtain an authorized token via GET /form
    let session_cookie = Cookie::build(DEFAULT_SESSION_ID_KEY, "SID-LOGIN")
        .path("/")
        .finish();
    let req = test::TestRequest::get()
        .uri("/form")
        .cookie(session_cookie.clone())
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Extract authorized token cookie and use its value as header token
    let auth_token_cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == DEFAULT_CSRF_TOKEN_KEY)
        .map(|c| c.into_owned())
        .expect("authorized token cookie present");

    // Call /auth via GET (non-mutating) to rotate after login
    let req = test::TestRequest::get()
        .uri("/auth")
        .cookie(auth_token_cookie)
        .cookie(session_cookie.clone())
        .to_request();

    let auth_resp = test::call_service(&app, req).await;
    assert!(auth_resp.status().is_success());

    // Verify pre-session cookie was expired and authorized token cookie set
    let mut saw_expired_pre_session = false;
    let mut new_auth_cookie: Option<Cookie<'static>> = None;

    for c in auth_resp.response().cookies() {
        if c.name() == CSRF_PRE_SESSION_KEY {
            if let Some(ma) = c.max_age() {
                assert_eq!(ma, time::Duration::seconds(0));
                saw_expired_pre_session = true;
            }
        }

        if c.name() == DEFAULT_CSRF_TOKEN_KEY {
            new_auth_cookie = Some(c.into_owned());
        }
    }

    assert!(
        saw_expired_pre_session,
        "pre-session cookie should be expired"
    );

    let new_auth_cookie = new_auth_cookie.expect("authorized token cookie should be set");
    assert!(!new_auth_cookie.value().is_empty());

    // Subsequent POST /submit with header token and session cookie should succeed
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((
            DEFAULT_CSRF_TOKEN_HEADER,
            new_auth_cookie.value().to_string(),
        ))
        .cookie(new_auth_cookie)
        .cookie(session_cookie)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn rotates_token_via_request_ext_synchronizer() {
    // Build app with SynchronizerToken pattern
    let cfg = CsrfMiddlewareConfig::synchronizer_token(&get_secret_key());
    let app = build_app_with_auth(cfg).await;

    // Prepare a session id cookie and obtain an authorized token via GET /form
    let session_cookie = Cookie::build(DEFAULT_SESSION_ID_KEY, "SID-LOGIN")
        .path("/")
        .finish();
    let req = test::TestRequest::get()
        .uri("/form")
        .cookie(session_cookie.clone())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // capture session cookie by configured name
    let as_cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == DEFAULT_SESSION_ID_KEY)
        .map(|c| c.into_owned())
        .expect("session cookie present");

    let body = test::read_body(resp).await;
    let token_before = String::from_utf8(body.to_vec()).unwrap();
    let token_before = token_before.strip_prefix("token:").unwrap().to_string();

    // Call /auth via GET (non-mutating) to rotate after login
    let req = test::TestRequest::get()
        .uri("/auth")
        .cookie(as_cookie.clone())
        .to_request();
    let auth_resp = test::call_service(&app, req).await;
    assert!(auth_resp.status().is_success());

    // capture potentially updated session cookie
    let as_cookie2 = auth_resp
        .response()
        .cookies()
        .find(|c| c.name() == DEFAULT_SESSION_ID_KEY)
        .map(|c| c.into_owned())
        .unwrap_or_else(|| as_cookie.clone());

    // After rotation, GET /form with same session should yield a new authorized token
    let req = test::TestRequest::get()
        .uri("/form")
        .cookie(as_cookie2.clone())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body = test::read_body(resp).await;
    let token_after = String::from_utf8(body.to_vec()).unwrap();
    let token_after = token_after.strip_prefix("token:").unwrap().to_string();
    assert_ne!(token_after, token_before, "token should rotate after /auth");

    // Use the rotated token in a POST /submit; should succeed
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, token_after))
        .cookie(as_cookie2)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
