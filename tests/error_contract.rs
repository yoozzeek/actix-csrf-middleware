mod common;

use actix_csrf_middleware::{
    CsrfError, CsrfMiddleware, CsrfMiddlewareConfig, CsrfPattern, CsrfToken,
    DEFAULT_CSRF_TOKEN_HEADER,
};
use actix_http::body::{EitherBody, MessageBody};
use actix_web::dev::ServiceResponse;
use actix_web::http::header::{self, HeaderName, HeaderValue};
use actix_web::http::StatusCode;
use actix_web::middleware::{ErrorHandlerResponse, ErrorHandlers};
use actix_web::{test, web, App, HttpResponse};

fn get_secret_key() -> Vec<u8> {
    b"super-secret-super-secret-super-secret-xx".to_vec()
}

async fn assert_json_error<B>(
    resp: ServiceResponse<B>,
    expected_status: StatusCode,
    expected_code: &str,
) where
    B: MessageBody,
{
    assert_eq!(resp.status(), expected_status);

    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    assert!(
        content_type.starts_with("application/json"),
        "expected JSON content-type, got {content_type:?}"
    );

    let body = test::read_body(resp).await;
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(body, format!(r#"{{"error":"{expected_code}"}}"#));
}

#[actix_web::test]
async fn invalid_token_renders_json_contract() {
    let app =
        common::build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, cookies) =
        common::token_and_cookies_for(&app, &CsrfPattern::DoubleSubmitCookie).await;

    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, "forged-token-not-an-hmac"));

    for cookie in cookies {
        req = req.cookie(cookie);
    }

    let resp = test::call_service(&app, req.to_request()).await;
    assert_json_error(resp, StatusCode::BAD_REQUEST, "csrf_token_invalid").await;
}

#[actix_web::test]
async fn missing_token_renders_json_contract() {
    let app =
        common::build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("unrelated=field")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_json_error(resp, StatusCode::BAD_REQUEST, "csrf_token_missing").await;
}

#[actix_web::test]
async fn multipart_without_optin_renders_json_contract() {
    let app =
        common::build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=----xyz",
        ))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_json_error(resp, StatusCode::BAD_REQUEST, "csrf_multipart_not_enabled").await;
}

#[actix_web::test]
async fn rejected_origin_renders_json_contract() {
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())
        .with_enforce_origin(true, vec!["https://allowed.example".to_string()]);
    let app = common::build_app(cfg).await;

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((header::ORIGIN, "https://evil.example"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_json_error(resp, StatusCode::FORBIDDEN, "csrf_origin_rejected").await;
}

#[actix_web::test]
async fn oversized_body_renders_json_contract() {
    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key()).with_max_body_bytes(8);
    let app = common::build_app(cfg).await;

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("csrf_token=way-past-the-eight-byte-limit")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_json_error(resp, StatusCode::PAYLOAD_TOO_LARGE, "csrf_body_too_large").await;
}

// The middleware stores the typed error in the response
// extensions; an `ErrorHandlers` can recover it and act
// on the stable code without parsing the body.
fn tag_csrf_error<B>(mut res: ServiceResponse<B>) -> actix_web::Result<ErrorHandlerResponse<B>> {
    let code = res
        .response()
        .extensions()
        .get::<CsrfError>()
        .map(|err| err.code());

    if let Some(code) = code {
        res.response_mut().headers_mut().insert(
            HeaderName::from_static("x-csrf-code"),
            HeaderValue::from_static(code),
        );
    }

    Ok(ErrorHandlerResponse::Response(res.map_into_left_body()))
}

#[actix_web::test]
async fn error_handlers_recovers_typed_error_from_extensions() {
    let app = test::init_service(
        App::new()
            .wrap(CsrfMiddleware::new(
                CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key()),
            ))
            .wrap(ErrorHandlers::<EitherBody<_>>::new().default_handler(tag_csrf_error))
            .route(
                "/submit",
                web::post().to(|_c: CsrfToken| async { HttpResponse::Ok().body("OK") }),
            ),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, "forged-token-not-an-hmac"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let recovered = resp
        .headers()
        .get("x-csrf-code")
        .and_then(|v| v.to_str().ok());

    assert_eq!(recovered, Some("csrf_token_invalid"));
}
