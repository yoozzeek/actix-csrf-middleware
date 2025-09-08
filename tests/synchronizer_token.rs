mod common;

use actix_csrf_middleware::{
    CsrfMiddlewareConfig, CsrfPattern, DEFAULT_CSRF_ANON_TOKEN_KEY, DEFAULT_CSRF_TOKEN_FIELD,
    DEFAULT_CSRF_TOKEN_HEADER, DEFAULT_CSRF_TOKEN_KEY, DEFAULT_SESSION_ID_KEY,
};
use actix_http::body::{BoxBody, EitherBody};
use actix_http::{Request, StatusCode};
use actix_web::cookie::Cookie;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::header::ContentType;
use actix_web::test;
use common::*;

fn get_secret_key() -> Vec<u8> {
    b"super-secret".to_vec()
}

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
        DEFAULT_SESSION_ID_KEY
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
pub async fn token_cookie_auth<S>(
    app: &S,
    session_id_cookie_name: Option<&str>,
) -> (String, Cookie<'static>)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    // First GET: obtain session cookie
    let (_anon_token, session_cookie) = token_cookie(app, session_id_cookie_name).await;

    // Second GET with session cookie: obtain authorized token
    let req2 = test::TestRequest::get()
        .uri("/form")
        .cookie(session_cookie.clone())
        .to_request();
    let resp2 = test::call_service(&app, req2).await;

    let updated_session_cookie = resp2
        .response()
        .cookies()
        .find(|c| c.name() == DEFAULT_SESSION_ID_KEY)
        .map(|c| c.into_owned())
        .unwrap_or_else(|| session_cookie.clone());

    let body2 = test::read_body(resp2).await;
    let token2 = String::from_utf8(body2.to_vec()).unwrap();
    let token2 = token2.strip_prefix("token:").unwrap().to_string();

    (token2, updated_session_cookie)
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn test_synchronizer_token_behavior() {
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token(&get_secret_key())).await;
    let (anon_token, session_cookie) = token_cookie(&app, None).await;

    // After login (session cookie present), token should rotate on next GET
    let req2 = test::TestRequest::get()
        .uri("/form")
        .cookie(session_cookie.clone())
        .to_request();
    let resp2 = test::call_service(&app, req2).await;
    assert!(resp2.status().is_success());

    // capture updated session cookie
    let updated_session_cookie = resp2
        .response()
        .cookies()
        .find(|c| c.name() == DEFAULT_SESSION_ID_KEY)
        .map(|c| c.into_owned())
        .unwrap_or_else(|| session_cookie.clone());

    let body = test::read_body(resp2).await;
    let auth_token = String::from_utf8(body.to_vec()).unwrap();
    let auth_token = auth_token.strip_prefix("token:").unwrap().to_string();

    assert_ne!(
        anon_token, auth_token,
        "Token should rotate on login (anon -> auth)"
    );

    // POST must succeed with authorized token
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, auth_token.clone()))
        .cookie(updated_session_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Fetch new token after POST - should be different
    let (new_auth_token, _) = token_cookie_auth(&app, None).await;
    assert_ne!(
        auth_token, new_auth_token,
        "Token should refresh on POST mutation"
    );
}

#[cfg(feature = "actix-session")]
#[actix_web::test]
async fn custom_config_header_name() {
    const HEADER_NAME: &str = "custom-header";

    let cfg = CsrfMiddlewareConfig {
        pattern: CsrfPattern::SynchronizerToken,
        manual_multipart: false,
        session_id_cookie_name: DEFAULT_SESSION_ID_KEY.to_string(),
        token_cookie_name: DEFAULT_CSRF_TOKEN_KEY.to_string(),
        anon_token_cookie_name: DEFAULT_CSRF_ANON_TOKEN_KEY.to_string(),
        anon_session_key_name: format!("{}-anon", DEFAULT_CSRF_TOKEN_KEY),
        token_form_field: "myfield".to_string(),
        token_header_name: HEADER_NAME.to_string(),
        token_cookie_config: None,
        secret_key: get_secret_key(),
        skip_for: vec![],
        enforce_origin: false,
        allowed_origins: vec![],
        max_body_bytes: 2 * 1024 * 1024,
    };
    let app = build_app(cfg).await;
    let (token, token_cookie) = { token_cookie_auth(&app, None).await };

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
        session_id_cookie_name: DEFAULT_SESSION_ID_KEY.to_string(),
        token_cookie_name: COOKIE_NAME.to_string(),
        anon_token_cookie_name: DEFAULT_CSRF_ANON_TOKEN_KEY.to_string(),
        anon_session_key_name: format!("{}-anon", DEFAULT_CSRF_TOKEN_KEY),
        token_form_field: DEFAULT_CSRF_TOKEN_FIELD.to_string(),
        token_header_name: DEFAULT_CSRF_TOKEN_HEADER.to_string(),
        token_cookie_config: None,
        secret_key: get_secret_key(),
        skip_for: vec![],
        enforce_origin: false,
        allowed_origins: vec![],
        max_body_bytes: 2 * 1024 * 1024,
    };
    let app = build_app(cfg).await;
    let (token, token_cookie) = { token_cookie_auth(&app, None).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, token))
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
        session_id_cookie_name: DEFAULT_SESSION_ID_KEY.to_string(),
        token_cookie_name: DEFAULT_CSRF_TOKEN_KEY.to_string(),
        anon_token_cookie_name: DEFAULT_CSRF_ANON_TOKEN_KEY.to_string(),
        anon_session_key_name: format!("{}-anon", DEFAULT_CSRF_TOKEN_KEY),
        token_form_field: FIELD_NAME.to_string(),
        token_header_name: "myheader".to_string(),
        token_cookie_config: None,
        secret_key: get_secret_key(),
        skip_for: vec![],
        enforce_origin: false,
        allowed_origins: vec![],
        max_body_bytes: 2 * 1024 * 1024,
    };
    let app = build_app(cfg).await;
    let (token, token_cookie) = { token_cookie_auth(&app, None).await };

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
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token(&get_secret_key())).await;
    let (token, token_cookie) = { token_cookie_auth(&app, None).await };

    let large = "a".repeat(1024 * 1024);
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, token))
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
    let app = build_app(CsrfMiddlewareConfig::synchronizer_token(&get_secret_key())).await;
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
