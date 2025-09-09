use actix_csrf_middleware::{
    CsrfMiddleware, CsrfMiddlewareConfig, CsrfPattern, DEFAULT_CSRF_TOKEN_FIELD,
};
use actix_web::{test, web, App, HttpResponse};

mod common;

#[actix_web::test]
async fn returns_413_when_body_exceeds_limit() {
    let secret = b"limit-test-limit-test-limit-test-1234";
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(secret).with_max_body_bytes(64);
    let app = test::init_service(
        App::new()
            .wrap(CsrfMiddleware::new(cfg))
            .configure(common::configure_routes),
    )
    .await;

    // Acquire cookies and a token (we won't use header token, so middleware reads body)
    let (token, cookies) =
        common::token_and_cookies_for(&app, &CsrfPattern::DoubleSubmitCookie).await;

    let large_token = format!("{}{}", token, "X".repeat(2048));
    let body = serde_json::json!({ DEFAULT_CSRF_TOKEN_FIELD: large_token });

    let mut req = test::TestRequest::post().uri("/submit").set_json(body);
    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(&app, req.to_request()).await;
    assert_eq!(
        resp.status(),
        actix_web::http::StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[actix_web::test]
async fn skip_for_bypasses_csrf_validation_on_custom_route() {
    let secret = b"skip-test-skip-test-skip-test-123456";
    let mut cfg = CsrfMiddlewareConfig::double_submit_cookie(secret);
    cfg = cfg.with_skip_for(vec!["/open".to_string()]);

    // Custom app with an "/open" route that doesn't use CsrfToken extractor
    let app = test::init_service(App::new().wrap(CsrfMiddleware::new(cfg)).route(
        "/open",
        web::post().to(|| async { HttpResponse::Ok().body("OK") }),
    ))
    .await;

    let req = test::TestRequest::post().uri("/open").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}
