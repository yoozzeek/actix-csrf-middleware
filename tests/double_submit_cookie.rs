mod common;
use actix_csrf_middleware::{
    CsrfDoubleSubmitCookie, CsrfMiddlewareConfig, CsrfPattern, DEFAULT_COOKIE_NAME,
    DEFAULT_FORM_FIELD, DEFAULT_HEADER, DEFAULT_SESSION_ID_COOKIE_NAME,
};
use actix_http::Request;
use actix_http::body::{BoxBody, EitherBody};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::header::ContentType;
use actix_web::{HttpResponse, test};
use common::*;
use serde_json::json;
use std::rc::Rc;

fn get_secret_key() -> Vec<u8> {
    b"super-secret".to_vec()
}

pub async fn token_cookie<S>(
    app: &S,
    session_id_cookie_name: Option<&str>,
    token_cookie_name: Option<&str>,
) -> (String, Cookie<'static>, Cookie<'static>)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let req = test::TestRequest::get().uri("/form").to_request();
    let resp = test::call_service(&app, req).await;

    let session_id_cookie_name = if let Some(session_id) = session_id_cookie_name {
        session_id
    } else {
        DEFAULT_SESSION_ID_COOKIE_NAME
    };

    let session_id_cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == session_id_cookie_name)
        .map(|c| c.into_owned())
        .unwrap();

    let token_cookie_name = if let Some(name) = token_cookie_name {
        name
    } else {
        DEFAULT_COOKIE_NAME
    };

    let token_cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == token_cookie_name)
        .map(|c| c.into_owned())
        .unwrap();

    let body = test::read_body(resp).await;
    let token = String::from_utf8(body.to_vec()).unwrap();
    let token = token.strip_prefix("token:").unwrap().to_string();

    (token, token_cookie, session_id_cookie)
}

#[actix_web::test]
async fn valid_csrf_header() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (token, token_cookie, session_id_cookie) = { token_cookie(&app, None, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token))
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn valid_csrf_form_field() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (token, token_cookie, session_id_cookie) = { token_cookie(&app, None, None).await };

    let form = format!("csrf_token={}", &token);
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::form_url_encoded())
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn valid_csrf_json_payload() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (token, token_cookie, session_id_cookie) = { token_cookie(&app, None, None).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .set_json(json!({
            "csrf_token": token
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn invalid_csrf_header() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_id_cookie) = { token_cookie(&app, None, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .insert_header((DEFAULT_HEADER, "wrong-token"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}

#[actix_web::test]
async fn invalid_csrf_form_field() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_id_cookie) = { token_cookie(&app, None, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::form_url_encoded())
        .set_payload("csrf_token=wrong-token")
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}

#[actix_web::test]
async fn invalid_csrf_json_payload() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_id_cookie) = { token_cookie(&app, None, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .set_json(json!({
            "csrf_token": "wrong-token",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}

#[actix_web::test]
async fn missing_csrf_token() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_id_cookie) = { token_cookie(&app, None, None).await };
    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}

#[actix_web::test]
async fn token_refresh_on_successful_mutation() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (token1, token1_cookie, session1_cookie) = { token_cookie(&app, None, None).await };

    // POST with valid token
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token1.clone()))
        .cookie(token1_cookie)
        .cookie(session1_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    // GET new token (should be refreshed)
    let (new_token, _token_cookie, _session_id_cookie) = { token_cookie(&app, None, None).await };
    assert_ne!(token1, new_token, "Token should be refreshed after POST");
}

#[actix_web::test]
async fn custom_config_header_name() {
    const HEADER_NAME: &str = "custom-header";

    let cfg = CsrfMiddlewareConfig {
        pattern: CsrfPattern::DoubleSubmitCookie,
        session_id_cookie_name: DEFAULT_SESSION_ID_COOKIE_NAME.to_string(),
        token_cookie_name: DEFAULT_COOKIE_NAME.to_string(),
        token_form_field: "myfield".to_string(),
        token_header_name: HEADER_NAME.to_string(),
        token_cookie_config: Some(CsrfDoubleSubmitCookie {
            http_only: false,
            secure: true,
            same_site: SameSite::Lax,
        }),
        secret_key: Some(get_secret_key()),
        skip_for: vec![],
        on_error: Rc::new(|_| HttpResponse::BadRequest().body("BAD!")),
    };
    let app = build_app(cfg).await;
    let (token, token_cookie, session_id_cookie) = { token_cookie(&app, None, None).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((HEADER_NAME, token))
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn custom_config_cookie_name() {
    const COOKIE_NAME: &str = "custom-cookie";

    let cfg = CsrfMiddlewareConfig {
        pattern: CsrfPattern::DoubleSubmitCookie,
        session_id_cookie_name: DEFAULT_SESSION_ID_COOKIE_NAME.to_string(),
        token_cookie_name: COOKIE_NAME.to_string(),
        token_form_field: DEFAULT_FORM_FIELD.to_string(),
        token_header_name: DEFAULT_HEADER.to_string(),
        token_cookie_config: Some(CsrfDoubleSubmitCookie {
            http_only: false,
            secure: true,
            same_site: SameSite::Lax,
        }),
        secret_key: Some(get_secret_key()),
        skip_for: vec![],
        on_error: Rc::new(|_| HttpResponse::BadRequest().body("BAD!")),
    };
    let app = build_app(cfg).await;
    let (token, token_cookie, session_id_cookie) =
        { token_cookie(&app, None, Some(COOKIE_NAME)).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token))
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn custom_config_form_field_name() {
    const FIELD_NAME: &str = "custom-cookie";

    let cfg = CsrfMiddlewareConfig {
        pattern: CsrfPattern::DoubleSubmitCookie,
        session_id_cookie_name: DEFAULT_SESSION_ID_COOKIE_NAME.to_string(),
        token_cookie_name: DEFAULT_COOKIE_NAME.to_string(),
        token_form_field: FIELD_NAME.to_string(),
        token_header_name: "myheader".to_string(),
        token_cookie_config: Some(CsrfDoubleSubmitCookie {
            http_only: false,
            secure: true,
            same_site: SameSite::Lax,
        }),
        secret_key: Some(get_secret_key()),
        skip_for: vec![],
        on_error: Rc::new(|_| HttpResponse::BadRequest().body("BAD!")),
    };
    let app = build_app(cfg).await;
    let (token, token_cookie, session_id_cookie) = { token_cookie(&app, None, None).await };

    let form = format!("{}={}", FIELD_NAME, &token);
    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .insert_header(ContentType::form_url_encoded())
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn handles_large_chunked_body() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (token, token_cookie, session_id_cookie) = { token_cookie(&app, None, None).await };

    let large = "a".repeat(1024 * 1024);
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token))
        .insert_header(ContentType::form_url_encoded())
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .set_payload(large)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
async fn handles_malformed_json_body() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_cookie) = { token_cookie(&app, None, None).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .cookie(token_cookie)
        .cookie(session_cookie)
        .set_payload("{not: valid json")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(!resp.status().is_server_error());
}

#[actix_web::test]
async fn token_double_submit_and_mismatch() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (token, token_cookie, session_id_cookie) = { token_cookie(&app, None, None).await };

    // Double submit: header matches, body is wrong (should succeed)
    let form = "csrf_token=wrong_token".to_string();
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token))
        .insert_header(ContentType::form_url_encoded())
        .cookie(token_cookie.clone())
        .cookie(session_id_cookie.clone())
        .set_payload(form.clone())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Double submit: both wrong (should fail)
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, "bad"))
        .insert_header(ContentType::form_url_encoded())
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}
