use actix_csrf_middleware::{
    CsrfMiddleware, CsrfMiddlewareConfig, CsrfPattern, DEFAULT_CSRF_TOKEN_HEADER,
};
use actix_web::test;

mod common;

#[actix_web::test]
async fn enforce_origin_allows_allowed_origin_double_submit() {
    let secret = b"good-origin-good-origin-good-origin-123";
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(secret)
        .with_enforce_origin(true, vec!["https://good.example".to_string()]);
    let app = test::init_service(
        actix_web::App::new()
            .wrap(CsrfMiddleware::new(cfg))
            .configure(common::configure_routes),
    )
    .await;

    let (token, cookies) =
        common::token_and_cookies_for(&app, &CsrfPattern::DoubleSubmitCookie).await;

    let mut req = test::TestRequest::post().uri("/submit");
    for c in cookies {
        req = req.cookie(c);
    }
    req = req.insert_header((DEFAULT_CSRF_TOKEN_HEADER, token));
    req = req.insert_header(("Origin", "https://good.example"));

    let resp = test::call_service(&app, req.to_request()).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn enforce_origin_blocks_disallowed_origin_double_submit() {
    let secret = b"good-origin-good-origin-good-origin-123";
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(secret)
        .with_enforce_origin(true, vec!["https://good.example".to_string()]);
    let app = test::init_service(
        actix_web::App::new()
            .wrap(CsrfMiddleware::new(cfg))
            .configure(common::configure_routes),
    )
    .await;

    let (token, cookies) =
        common::token_and_cookies_for(&app, &CsrfPattern::DoubleSubmitCookie).await;

    let mut req = test::TestRequest::post().uri("/submit");
    for c in cookies {
        req = req.cookie(c);
    }
    req = req.insert_header((DEFAULT_CSRF_TOKEN_HEADER, token));
    req = req.insert_header(("Origin", "https://evil.example"));

    let resp = test::call_service(&app, req.to_request()).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn enforce_origin_uses_referer_when_origin_absent_double_submit() {
    let secret = b"good-origin-good-origin-good-origin-123";
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(secret)
        .with_enforce_origin(true, vec!["https://good.example".to_string()]);
    let app = test::init_service(
        actix_web::App::new()
            .wrap(CsrfMiddleware::new(cfg))
            .configure(common::configure_routes),
    )
    .await;

    let (token, cookies) =
        common::token_and_cookies_for(&app, &CsrfPattern::DoubleSubmitCookie).await;

    let mut req = test::TestRequest::post().uri("/submit");
    for c in cookies {
        req = req.cookie(c);
    }
    req = req.insert_header((DEFAULT_CSRF_TOKEN_HEADER, token));
    req = req.insert_header(("Referer", "https://good.example/path?q=1"));

    let resp = test::call_service(&app, req.to_request()).await;
    assert!(resp.status().is_success());
}
