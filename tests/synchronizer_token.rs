mod common;

use actix_csrf_middleware::{
    CsrfMiddlewareConfig, CsrfPattern, DEFAULT_COOKIE_NAME, DEFAULT_FORM_FIELD, DEFAULT_HEADER,
    DEFAULT_SESSION_ID_COOKIE_NAME,
};
use actix_http::body::{BoxBody, EitherBody};
use actix_http::{Request, StatusCode};
use actix_multipart::test::create_form_data_payload_and_headers;
use actix_web::cookie::Cookie;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::header::ContentType;
use actix_web::web::Bytes;
use actix_web::{HttpResponse, mime, test};
use common::*;
use serde_json::json;
use std::collections::HashSet;
use std::rc::Rc;

pub async fn token_cookie<S>(
    app: &S,
    session_id_cookie_name: Option<&str>,
) -> (String, Cookie<'static>)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let req = test::TestRequest::get().uri("/form").to_request();
    let resp = test::call_service(&app, req).await;

    let cookie_name = if let Some(session_id) = session_id_cookie_name {
        session_id
    } else {
        DEFAULT_SESSION_ID_COOKIE_NAME
    };

    let cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == cookie_name)
        .map(|c| c.into_owned())
        .unwrap();

    let body = test::read_body(resp).await;
    let token = String::from_utf8(body.to_vec()).unwrap();
    let token = token.strip_prefix("token:").unwrap().to_string();

    (token, cookie)
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn valid_csrf_header() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (token, token_cookie) = { token_cookie(&app, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token))
        .cookie(token_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn valid_csrf_form_field() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (token, token_cookie) = { token_cookie(&app, None).await };

    let form = format!("csrf_token={}", &token);
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::form_url_encoded())
        .cookie(token_cookie)
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn valid_csrf_json_payload() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (token, token_cookie) = { token_cookie(&app, None).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .cookie(token_cookie)
        .set_json(json!({
            "csrf_token": token
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn invalid_csrf_header() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (_token, token_cookie) = { token_cookie(&app, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(token_cookie)
        .insert_header((DEFAULT_HEADER, "wrong-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn invalid_csrf_form_field() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (_token, token_cookie) = { token_cookie(&app, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::form_url_encoded())
        .set_payload("csrf_token=wrong-token")
        .cookie(token_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn invalid_csrf_json_payload() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (_token, token_cookie) = { token_cookie(&app, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(token_cookie)
        .set_json(json!({
            "csrf_token": "wrong-token",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn missing_csrf_token() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (_token, token_cookie) = { token_cookie(&app, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(token_cookie)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn token_refresh_on_successful_mutation() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (token1, token1_cookie) = { token_cookie(&app, None).await };

    // POST with valid token
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token1.clone()))
        .cookie(token1_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // GET new token (should be refreshed)
    let (new_token, _token2_cookie) = { token_cookie(&app, None).await };
    assert_ne!(token1, new_token, "Token should be refreshed after POST");
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn synchronizer_token_format() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (token, _token_cookie) = token_cookie(&app, None).await;

    // Synchronizer token should be a 32-byte base64url encoded string (43 chars without padding)
    assert_eq!(
        token.len(),
        43,
        "Synchronizer token should be 43 characters (32 bytes base64url)"
    );

    // Should contain only valid base64url characters
    assert!(
        token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "Synchronizer token should contain only base64url characters"
    );

    // Should not contain HMAC format (no dot separator)
    assert!(
        !token.contains('.'),
        "Synchronizer token should not contain dot separator (not HMAC format)"
    );
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn csrf_token_rotation() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (initial_token, initial_token_cookie) = token_cookie(&app, None).await;

    // Perform a POST request with the initial token
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, initial_token.clone()))
        .cookie(initial_token_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Get a new token after the mutation
    let (new_token, _new_token_cookie) = token_cookie(&app, None).await;
    assert_ne!(
        initial_token, new_token,
        "CSRF token should be refreshed after mutation"
    );
    assert_eq!(
        new_token.len(),
        43,
        "Synchronizer token should be a 32-byte base64 string"
    );
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn custom_config_header_name() {
    const HEADER_NAME: &str = "custom-header";

    let cfg = CsrfMiddlewareConfig {
        pattern: CsrfPattern::SynchronizerToken,
        manual_multipart: false,
        session_id_cookie_name: DEFAULT_SESSION_ID_COOKIE_NAME.to_string(),
        token_cookie_name: DEFAULT_COOKIE_NAME.to_string(),
        token_form_field: "myfield".to_string(),
        token_header_name: HEADER_NAME.to_string(),
        token_cookie_config: None,
        secret_key: None,
        skip_for: vec![],
        on_error: Rc::new(|_| HttpResponse::BadRequest().body("BAD!")),
    };
    let app = build_app(cfg).await;
    let (token, token_cookie) = { token_cookie(&app, None).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((HEADER_NAME, token))
        .cookie(token_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn custom_config_cookie_name() {
    const COOKIE_NAME: &str = "custom-cookie";

    let cfg = CsrfMiddlewareConfig {
        pattern: CsrfPattern::SynchronizerToken,
        manual_multipart: false,
        session_id_cookie_name: DEFAULT_SESSION_ID_COOKIE_NAME.to_string(),
        token_cookie_name: COOKIE_NAME.to_string(),
        token_form_field: DEFAULT_FORM_FIELD.to_string(),
        token_header_name: DEFAULT_HEADER.to_string(),
        token_cookie_config: None,
        secret_key: None,
        skip_for: vec![],
        on_error: Rc::new(|_| HttpResponse::BadRequest().body("BAD!")),
    };
    let app = build_app(cfg).await;
    let (token, token_cookie) = { token_cookie(&app, None).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token))
        .cookie(token_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn custom_config_form_field_name() {
    const FIELD_NAME: &str = "custom-cookie";

    let cfg = CsrfMiddlewareConfig {
        pattern: CsrfPattern::SynchronizerToken,
        manual_multipart: false,
        session_id_cookie_name: DEFAULT_SESSION_ID_COOKIE_NAME.to_string(),
        token_cookie_name: DEFAULT_COOKIE_NAME.to_string(),
        token_form_field: FIELD_NAME.to_string(),
        token_header_name: "myheader".to_string(),
        token_cookie_config: None,
        secret_key: None,
        skip_for: vec![],
        on_error: Rc::new(|_| HttpResponse::BadRequest().body("BAD!")),
    };
    let app = build_app(cfg).await;
    let (token, token_cookie) = { token_cookie(&app, None).await };

    let form = format!("{}={}", FIELD_NAME, &token);
    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(token_cookie)
        .insert_header(ContentType::form_url_encoded())
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn handles_large_chunked_body() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (token, token_cookie) = { token_cookie(&app, None).await };

    let large = "a".repeat(1024 * 1024);
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token))
        .insert_header(ContentType::form_url_encoded())
        .cookie(token_cookie)
        .set_payload(large)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn handles_malformed_json_body() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (_token, token_cookie) = { token_cookie(&app, None).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .cookie(token_cookie)
        .set_payload("{not: valid json")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_client_error(),
        "malformed json body cannot be passed"
    )
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn multipart_form_data_not_enabled() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;
    let (_token, token_cookie) = token_cookie(&app, None).await;

    let (body, headers) = create_form_data_payload_and_headers(
        "foo",
        Some("lorem. txt".to_owned()),
        Some(mime::TEXT_PLAIN_UTF_8),
        Bytes::from_static(b"Lorem ipsum dolor sit amet"),
    );

    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(token_cookie);

    let req = headers
        .into_iter()
        .fold(req, |req, hdr| req.insert_header(hdr))
        .set_payload(body)
        .to_request();

    let resp = test::call_service(&app, req).await;

    assert!(
        resp.status().is_client_error(),
        "multipart form data is not enabled by csrf config"
    )
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn multipart_form_data_enabled() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token().with_multipart(true)).await;
    let (token, token_cookie) = token_cookie(&app, None).await;

    // Create multipart form data with CSRF token
    let boundary = "----formdata-test-boundary";
    let mut form_data = Vec::new();

    // Add CSRF token field
    form_data.extend_from_slice("------formdata-test-boundary\r\n".to_string().as_bytes());
    form_data.extend_from_slice(b"Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n");
    form_data.extend_from_slice(token.as_bytes());
    form_data.extend_from_slice(b"\r\n");

    // Add file field
    form_data.extend_from_slice("------formdata-test-boundary\r\n".to_string().as_bytes());
    form_data.extend_from_slice(
        b"Content-Disposition: form-data; name=\"foo\"; filename=\"lorem.txt\"\r\n",
    );
    form_data.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n\r\n");
    form_data.extend_from_slice(b"Lorem ipsum dolor sit amet");
    form_data.extend_from_slice(b"\r\n");
    form_data.extend_from_slice("------formdata-test-boundary--\r\n".to_string().as_bytes());

    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(token_cookie)
        .insert_header((
            "Content-Type",
            "multipart/form-data; boundary=----formdata-test-boundary".to_string(),
        ))
        .set_payload(Bytes::from(form_data))
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Now it should succeed since we provided the CSRF token
    assert!(
        resp.status().is_success(),
        "multipart form data with CSRF token should succeed"
    );
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn token_uniqueness() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token()).await;

    const MAX_COUNT: i32 = 100;
    let mut tokens = HashSet::new();
    for _ in 0..MAX_COUNT {
        let (token, _) = token_cookie(&app, None).await;
        tokens.insert(token);
    }

    assert_eq!(
        tokens.len() as i32,
        MAX_COUNT,
        "CSRF tokens should be unique"
    );
}
