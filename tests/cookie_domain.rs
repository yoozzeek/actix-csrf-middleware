mod common;

use actix_csrf_middleware::{
    CSRF_PRE_SESSION_KEY, CsrfMiddleware, CsrfMiddlewareConfig, CsrfRequestExt,
    DEFAULT_CSRF_ANON_TOKEN_KEY, DEFAULT_CSRF_TOKEN_HEADER, DEFAULT_CSRF_TOKEN_KEY,
    DEFAULT_SESSION_ID_KEY,
};
use actix_http::Request;
use actix_http::body::{BoxBody, EitherBody};
#[cfg(feature = "actix-session")]
use actix_session::{
    SessionMiddleware, config::CookieContentSecurity, storage::CookieSessionStore,
};
use actix_web::cookie::{Cookie, time};
#[cfg(feature = "actix-session")]
use actix_web::cookie::{Key, SameSite};
use actix_web::dev::{Service, ServiceResponse};
use actix_web::{App, HttpRequest, HttpResponse, test, web};

const COOKIE_DOMAIN: &str = ".example.com";

// Set-Cookie re-parse strips the leading dot (RFC 6265).
const EXPECTED_DOMAIN: &str = "example.com";

fn get_secret_key() -> Vec<u8> {
    b"domain-secret-domain-secret-domain-12345".to_vec()
}

fn is_csrf_cookie(name: &str) -> bool {
    name == CSRF_PRE_SESSION_KEY
        || name == DEFAULT_CSRF_TOKEN_KEY
        || name == DEFAULT_CSRF_ANON_TOKEN_KEY
}

// Every cookie the middleware owns must carry the
// configured domain; the session cookie belongs to
// `actix-session` and is excluded.
fn assert_csrf_cookies_domained<B>(resp: &ServiceResponse<B>) -> usize {
    let mut checked = 0;
    for c in resp.response().cookies() {
        if is_csrf_cookie(c.name()) {
            assert_eq!(
                c.domain(),
                Some(EXPECTED_DOMAIN),
                "cookie `{}` must carry the configured domain",
                c.name()
            );

            checked += 1;
        }
    }

    checked
}

async fn build_app(
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

        app.configure(common::configure_routes)
            .service(web::resource("/auth").route(web::get().to(auth_handler)))
            .service(web::resource("/logout").route(web::post().to(logout_handler)))
    })
    .await
}

async fn auth_handler(req: HttpRequest) -> actix_web::Result<HttpResponse> {
    let session_id = req
        .cookie(DEFAULT_SESSION_ID_KEY)
        .map(|c| c.value().to_owned())
        .unwrap_or_else(|| "missing-session-id".to_string());

    let mut resp = HttpResponse::Ok();
    req.rotate_csrf_after_login(&session_id, &mut resp)?;

    Ok(resp.finish())
}

async fn logout_handler(req: HttpRequest) -> actix_web::Result<HttpResponse> {
    let mut resp = HttpResponse::Ok();
    req.rotate_csrf_after_logout(&mut resp)?;

    Ok(resp.finish())
}

#[actix_web::test]
async fn cookie_domain_applied_double_submit_cookie() {
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())
        .with_cookie_domain(COOKIE_DOMAIN);
    let app = build_app(cfg).await;

    // Anonymous issue:
    // pre-session + anon token cookies.
    let req = test::TestRequest::get().uri("/form").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let n = assert_csrf_cookies_domained(&resp);
    assert!(n >= 2, "anon issue must set 2 domained cookies, saw {n}");

    // Authorized issue:
    // token bound to a session id.
    let session_cookie = Cookie::build(DEFAULT_SESSION_ID_KEY, "SID-DOMAIN")
        .path("/")
        .finish();
    let req = test::TestRequest::get()
        .uri("/form")
        .cookie(session_cookie.clone())
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    assert_csrf_cookies_domained(&resp);

    let auth_token_cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == DEFAULT_CSRF_TOKEN_KEY)
        .map(|c| c.into_owned())
        .expect("authorized token cookie present");

    assert_eq!(auth_token_cookie.domain(), Some(EXPECTED_DOMAIN));

    // Login rotation:
    // new token issued, anon + pre-session expired.
    let req = test::TestRequest::get()
        .uri("/auth")
        .cookie(auth_token_cookie.clone())
        .cookie(session_cookie.clone())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let n = assert_csrf_cookies_domained(&resp);
    assert!(n >= 1, "login rotation must issue a domained token cookie");

    // Logout teardown:
    // every expiring cookie must carry the same domain,
    // or the browser keeps the old-scoped cookie
    // and the token never clears.
    let req = test::TestRequest::post()
        .uri("/logout")
        .insert_header((
            DEFAULT_CSRF_TOKEN_HEADER,
            auth_token_cookie.value().to_string(),
        ))
        .cookie(auth_token_cookie)
        .cookie(session_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let expired_domained = |name: &str| {
        resp.response().cookies().any(|c| {
            c.name() == name
                && c.max_age() == Some(time::Duration::seconds(0))
                && c.domain() == Some(EXPECTED_DOMAIN)
        })
    };

    assert!(
        expired_domained(DEFAULT_SESSION_ID_KEY),
        "session id expiry must carry the domain"
    );
    assert!(
        expired_domained(DEFAULT_CSRF_TOKEN_KEY),
        "token expiry must carry the domain"
    );
    assert!(
        expired_domained(DEFAULT_CSRF_ANON_TOKEN_KEY),
        "anon token expiry must carry the domain"
    );
    assert!(
        expired_domained(CSRF_PRE_SESSION_KEY),
        "pre-session expiry must carry the domain"
    );
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn cookie_domain_applied_synchronizer() {
    let cfg = CsrfMiddlewareConfig::synchronizer_token(&get_secret_key())
        .with_cookie_domain(COOKIE_DOMAIN);
    let app = build_app(cfg).await;

    // Anonymous issue sets the pre-session cookie with the domain.
    let req = test::TestRequest::get().uri("/form").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let pre = resp
        .response()
        .cookies()
        .find(|c| c.name() == CSRF_PRE_SESSION_KEY)
        .expect("pre-session cookie present");

    assert_eq!(pre.domain(), Some(EXPECTED_DOMAIN));

    let session_cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == DEFAULT_SESSION_ID_KEY)
        .map(|c| c.into_owned())
        .expect("session cookie present");
    let body = test::read_body(resp).await;
    let token = String::from_utf8(body.to_vec()).unwrap();
    let token = token.strip_prefix("token:").unwrap().to_string();

    // Logout teardown expires the pre-session
    // marker with the same domain.
    let req = test::TestRequest::post()
        .uri("/logout")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, token))
        .cookie(session_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let expired_pre = resp.response().cookies().any(|c| {
        c.name() == CSRF_PRE_SESSION_KEY
            && c.max_age() == Some(time::Duration::seconds(0))
            && c.domain() == Some(EXPECTED_DOMAIN)
    });

    assert!(expired_pre, "pre-session expiry must carry the domain");
}
