mod common;

use actix_csrf_middleware::{
    CSRF_PRE_SESSION_KEY, CsrfMiddleware, CsrfMiddlewareConfig, CsrfRequestExt,
    DEFAULT_CSRF_ANON_TOKEN_KEY, DEFAULT_CSRF_TOKEN_HEADER, DEFAULT_CSRF_TOKEN_KEY,
    DEFAULT_SESSION_ID_KEY, TokenClass, generate_hmac_token_ctx, validate_hmac_token_ctx,
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
use actix_web::http::header;
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

fn expired_host_only(resp: &ServiceResponse<EitherBody<BoxBody>>, name: &str) -> bool {
    resp.response().cookies().any(|c| {
        c.name() == name && c.max_age() == Some(time::Duration::seconds(0)) && c.domain().is_none()
    })
}

fn fresh_domained(resp: &ServiceResponse<EitherBody<BoxBody>>, name: &str) -> bool {
    resp.response().cookies().any(|c| {
        c.name() == name
            && c.domain() == Some(EXPECTED_DOMAIN)
            && c.max_age() != Some(time::Duration::seconds(0))
            && !c.value().is_empty()
    })
}

fn issued_token(resp: &ServiceResponse<EitherBody<BoxBody>>) -> String {
    resp.response()
        .cookies()
        .find(|c| {
            c.name() == DEFAULT_CSRF_TOKEN_KEY && c.max_age() != Some(time::Duration::seconds(0))
        })
        .map(|c| c.value().to_owned())
        .expect("a token cookie must be issued")
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

#[actix_web::test]
async fn duplicate_token_cookie_evicted_and_reminted() {
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())
        .with_cookie_domain(COOKIE_DOMAIN);
    let app = build_app(cfg).await;

    let req = test::TestRequest::get()
        .uri("/form")
        .insert_header((
            header::COOKIE,
            "id=SID-DUP; CSRF=stale-twin; CSRF=live-twin",
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    assert!(
        expired_host_only(&resp, DEFAULT_CSRF_TOKEN_KEY),
        "host-only twin of the token cookie must be evicted"
    );
    assert!(
        fresh_domained(&resp, DEFAULT_CSRF_TOKEN_KEY),
        "a replacement token must be minted in the configured scope"
    );
}

#[actix_web::test]
async fn duplicate_pre_session_rotates_instead_of_trusting_first() {
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())
        .with_cookie_domain(COOKIE_DOMAIN);
    let app = build_app(cfg).await;

    let req = test::TestRequest::get().uri("/form").to_request();
    let resp = test::call_service(&app, req).await;
    let valid = resp
        .response()
        .cookies()
        .find(|c| c.name() == CSRF_PRE_SESSION_KEY)
        .map(|c| c.value().to_owned())
        .expect("anonymous issue sets a pre-session");

    let jar = format!("{CSRF_PRE_SESSION_KEY}={valid}; {CSRF_PRE_SESSION_KEY}={valid}");
    let req = test::TestRequest::get()
        .uri("/form")
        .insert_header((header::COOKIE, jar))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    assert!(
        expired_host_only(&resp, CSRF_PRE_SESSION_KEY),
        "host-only twin of the pre-session cookie must be evicted"
    );

    let issued = resp
        .response()
        .cookies()
        .find(|c| {
            c.name() == CSRF_PRE_SESSION_KEY && c.max_age() != Some(time::Duration::seconds(0))
        })
        .map(|c| c.into_owned())
        .expect("a fresh pre-session must be issued");

    assert_eq!(issued.domain(), Some(EXPECTED_DOMAIN));
    assert_ne!(
        issued.value(),
        valid,
        "a duplicated pre-session must not be adopted"
    );
}

#[actix_web::test]
async fn rejected_mutating_request_still_evicts_twin() {
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())
        .with_cookie_domain(COOKIE_DOMAIN);
    let app = build_app(cfg).await;

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((
            header::COOKIE,
            "id=SID-DUP; CSRF=stale-twin; CSRF=live-twin",
        ))
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, "not-a-valid-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400, "an invalid token is still rejected");
    assert!(
        expired_host_only(&resp, DEFAULT_CSRF_TOKEN_KEY),
        "rejections must carry the eviction, or the client never recovers"
    );
}

#[actix_web::test]
async fn token_bound_to_dead_session_id_is_reminted() {
    let secret = get_secret_key();
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&secret).with_cookie_domain(COOKIE_DOMAIN);
    let app = build_app(cfg).await;

    let stale = generate_hmac_token_ctx(TokenClass::Authorized, "SID-OLD", &secret);
    let req = test::TestRequest::get()
        .uri("/form")
        .insert_header((
            header::COOKIE,
            format!("{DEFAULT_SESSION_ID_KEY}=SID-NEW; {DEFAULT_CSRF_TOKEN_KEY}={stale}"),
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());

    let issued = issued_token(&resp);

    assert_ne!(issued, stale, "a token bound elsewhere must not be adopted");
    assert!(
        validate_hmac_token_ctx(
            TokenClass::Authorized,
            "SID-NEW",
            issued.as_bytes(),
            &secret
        )
        .unwrap(),
        "the replacement must be bound to the live session id"
    );
}

#[actix_web::test]
async fn rejection_remints_token_client_can_use() {
    let secret = get_secret_key();
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&secret).with_cookie_domain(COOKIE_DOMAIN);
    let app = build_app(cfg).await;

    let stale = generate_hmac_token_ctx(TokenClass::Authorized, "SID-OLD", &secret);
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((
            header::COOKIE,
            format!("{DEFAULT_SESSION_ID_KEY}=SID-NEW; {DEFAULT_CSRF_TOKEN_KEY}={stale}"),
        ))
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, stale.clone()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);

    let issued = issued_token(&resp);

    assert!(
        validate_hmac_token_ctx(
            TokenClass::Authorized,
            "SID-NEW",
            issued.as_bytes(),
            &secret
        )
        .unwrap(),
        "a POST-only client must be able to recover from the rejection"
    );
}

#[actix_web::test]
async fn missing_token_still_evicts_and_remints() {
    let secret = get_secret_key();
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&secret).with_cookie_domain(COOKIE_DOMAIN);
    let app = build_app(cfg).await;

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((
            header::COOKIE,
            "id=SID-NEW; CSRF=stale-twin; CSRF=live-twin",
        ))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(r#"{"unrelated":"field"}"#)
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
    assert!(
        expired_host_only(&resp, DEFAULT_CSRF_TOKEN_KEY),
        "a missing token must still carry the eviction"
    );

    let issued = issued_token(&resp);

    assert!(
        validate_hmac_token_ctx(
            TokenClass::Authorized,
            "SID-NEW",
            issued.as_bytes(),
            &secret
        )
        .unwrap()
    );
}

#[actix_web::test]
async fn duplicate_session_id_not_expired_on_safe_path() {
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())
        .with_cookie_domain(COOKIE_DOMAIN);
    let app = build_app(cfg).await;

    let req = test::TestRequest::get()
        .uri("/form")
        .insert_header((header::COOKIE, "id=SID-STALE; id=SID-LIVE"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    assert!(
        !resp
            .response()
            .cookies()
            .any(|c| c.name() == DEFAULT_SESSION_ID_KEY),
        "the middleware must not write a cookie it does not own"
    );
}

#[actix_web::test]
async fn duplicates_are_left_alone_without_configured_domain() {
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key());
    let app = build_app(cfg).await;

    let req = test::TestRequest::get()
        .uri("/form")
        .insert_header((
            header::COOKIE,
            "id=SID-DUP; CSRF=stale-twin; CSRF=live-twin",
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    assert!(
        !expired_host_only(&resp, DEFAULT_CSRF_TOKEN_KEY),
        "without a domain there is no other scope to evict"
    );
}

#[actix_web::test]
async fn cookieless_rejection_mints_nothing() {
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())
        .with_cookie_domain(COOKIE_DOMAIN);
    let app = build_app(cfg).await;

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, "forged-token-not-an-hmac"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
    assert!(
        resp.response().cookies().next().is_none(),
        "a cookieless cross-site POST must not rotate a client's token"
    );
}

#[actix_web::test]
async fn rejection_without_pre_session_mints_nothing() {
    let secret = get_secret_key();
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&secret).with_cookie_domain(COOKIE_DOMAIN);
    let app = build_app(cfg).await;

    let orphan = generate_hmac_token_ctx(TokenClass::Anonymous, "DEAD-PRE-SESSION", &secret);
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((
            header::COOKIE,
            format!("{DEFAULT_CSRF_ANON_TOKEN_KEY}={orphan}"),
        ))
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, orphan.clone()))
        .to_request();

    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 400);
    assert!(
        !resp
            .response()
            .cookies()
            .any(|c| c.name() == DEFAULT_CSRF_ANON_TOKEN_KEY),
        "the response persists no pre-session, so a token bound to one cannot validate"
    );
}

#[actix_web::test]
async fn duplicate_scan_survives_jar_larger_than_u8() {
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())
        .with_cookie_domain(COOKIE_DOMAIN);
    let app = build_app(cfg).await;

    let twins = std::iter::repeat_n(format!("{DEFAULT_CSRF_TOKEN_KEY}=x"), 300)
        .collect::<Vec<_>>()
        .join("; ");

    let req = test::TestRequest::get()
        .uri("/form")
        .insert_header((
            header::COOKIE,
            format!("{DEFAULT_SESSION_ID_KEY}=SID-MANY; {twins}"),
        ))
        .to_request();

    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    assert!(
        expired_host_only(&resp, DEFAULT_CSRF_TOKEN_KEY),
        "duplicate detection must not wrap on a jar of 256 or more"
    );
}
