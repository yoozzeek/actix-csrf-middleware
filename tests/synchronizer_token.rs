mod common;

use actix_csrf_middleware::{
    CsrfMiddlewareConfig, CsrfPattern, DEFAULT_COOKIE_NAME, DEFAULT_FORM_FIELD, DEFAULT_HEADER,
};
use actix_web::cookie::SameSite;
use actix_web::http::header::ContentType;
use actix_web::{HttpResponse, test};
use common::*;
use serde_json::json;
use std::rc::Rc;

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn valid_csrf_header() {
    let app = build_app(None).await;
    let (token, cookie) = { token_cookie(&app, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token))
        .cookie(cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn valid_csrf_form_field() {
    let app = build_app(None).await;
    let (token, cookie) = { token_cookie(&app, None).await };

    let form = format!("csrf_token={}", &token);
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::form_url_encoded())
        .cookie(cookie)
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn valid_csrf_json_payload() {
    let app = build_app(None).await;
    let (token, cookie) = { token_cookie(&app, None).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .cookie(cookie)
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
    let app = build_app(None).await;
    let (_token, cookie) = { token_cookie(&app, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(cookie)
        .insert_header((DEFAULT_HEADER, "wrong-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn invalid_csrf_form_field() {
    let app = build_app(None).await;
    let (_token, cookie) = { token_cookie(&app, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::form_url_encoded())
        .set_payload("csrf_token=wrong-token")
        .cookie(cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn invalid_csrf_json_payload() {
    let app = build_app(None).await;
    let (_token, cookie) = { token_cookie(&app, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(cookie)
        .set_json(json!({
            "csrf_token": "wrong-token",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn missing_csrf_token() {
    let app = build_app(None).await;
    let (_token, cookie) = { token_cookie(&app, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn token_refresh_on_successful_mutation() {
    let app = build_app(None).await;
    let (token1, cookie) = { token_cookie(&app, None).await };

    // POST with valid token
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token1.clone()))
        .cookie(cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    // GET new token (should be refreshed)
    let (new_token, _cookie) = { token_cookie(&app, None).await };
    assert_ne!(token1, new_token, "Token should be refreshed after POST");
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn custom_config_header_name() {
    const HEADER_NAME: &str = "custom-header";

    let cfg = CsrfMiddlewareConfig {
        pattern: CsrfPattern::SynchronizerToken,
        cookie_name: DEFAULT_COOKIE_NAME.to_string(),
        form_field: "myfield".to_string(),
        header_name: HEADER_NAME.to_string(),
        secure: false,
        same_site: SameSite::Lax,
        skip_for: vec![],
        on_error: Rc::new(|_| HttpResponse::BadRequest().body("BAD!")),
    };
    let app = build_app(Some(cfg)).await;
    let (token, cookie) = { token_cookie(&app, None).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((HEADER_NAME, token))
        .cookie(cookie)
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
        cookie_name: COOKIE_NAME.to_string(),
        form_field: DEFAULT_FORM_FIELD.to_string(),
        header_name: DEFAULT_HEADER.to_string(),
        secure: false,
        same_site: SameSite::Lax,
        skip_for: vec![],
        on_error: Rc::new(|_| HttpResponse::BadRequest().body("BAD!")),
    };
    let app = build_app(Some(cfg)).await;
    let (token, cookie) = { token_cookie(&app, None).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token))
        .cookie(cookie)
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
        cookie_name: DEFAULT_COOKIE_NAME.to_string(),
        form_field: FIELD_NAME.to_string(),
        header_name: "myheader".to_string(),
        secure: false,
        same_site: SameSite::Lax,
        skip_for: vec![],
        on_error: Rc::new(|_| HttpResponse::BadRequest().body("BAD!")),
    };
    let app = build_app(Some(cfg)).await;
    let (token, cookie) = { token_cookie(&app, None).await };

    let form = format!("{}={}", FIELD_NAME, &token);
    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(cookie)
        .insert_header(ContentType::form_url_encoded())
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn handles_large_chunked_body() {
    let app = build_app(None).await;
    let (token, cookie) = { token_cookie(&app, None).await };

    let large = "a".repeat(1024 * 1024);
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token))
        .insert_header(ContentType::form_url_encoded())
        .cookie(cookie)
        .set_payload(large)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn handles_malformed_json_body() {
    let app = build_app(None).await;
    let (_token, cookie) = { token_cookie(&app, None).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .cookie(cookie)
        .set_payload("{not: valid json")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(!resp.status().is_server_error());
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn token_double_submit_and_mismatch() {
    let app = build_app(None).await;
    let (token, cookie) = { token_cookie(&app, None).await };

    // Double submit: header matches, body is wrong (should succeed)
    let form = "csrf_token=wrong_token".to_string();
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token))
        .insert_header(ContentType::form_url_encoded())
        .cookie(cookie.clone())
        .set_payload(form.clone())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Double submit: both wrong (should fail)
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, "bad"))
        .insert_header(ContentType::form_url_encoded())
        .cookie(cookie)
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}
