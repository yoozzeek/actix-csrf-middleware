mod common;

use actix_csrf_middleware::{
    generate_random_token, CsrfDoubleSubmitCookie, CsrfMiddlewareConfig, CsrfPattern,
    CSRF_PRE_SESSION_KEY, DEFAULT_CSRF_ANON_TOKEN_KEY, DEFAULT_CSRF_TOKEN_FIELD,
    DEFAULT_CSRF_TOKEN_HEADER, DEFAULT_CSRF_TOKEN_KEY, DEFAULT_SESSION_ID_KEY,
};
use actix_http::body::{BoxBody, EitherBody};
use actix_http::{Request, StatusCode};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::header::ContentType;
use actix_web::test;
use common::*;
use hmac::Mac;

fn get_secret_key() -> Vec<u8> {
    b"super-secret-super-secret-super-secret-xx".to_vec()
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
        DEFAULT_SESSION_ID_KEY
    };

    let session_id_cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == session_id_cookie_name || c.name() == CSRF_PRE_SESSION_KEY)
        .map(|c| c.into_owned())
        .unwrap();

    // Prefer authorized cookie name; if not present (anon flow), fall back to anon cookie name
    let token_cookie = if let Some(name) = token_cookie_name {
        resp.response()
            .cookies()
            .find(|c| c.name() == name)
            .or_else(|| {
                resp.response().cookies().find(|c| {
                    c.name() == DEFAULT_CSRF_TOKEN_KEY || c.name() == DEFAULT_CSRF_ANON_TOKEN_KEY
                })
            })
            .map(|c| c.into_owned())
            .unwrap()
    } else {
        resp.response()
            .cookies()
            .find(|c| c.name() == DEFAULT_CSRF_TOKEN_KEY || c.name() == DEFAULT_CSRF_ANON_TOKEN_KEY)
            .map(|c| c.into_owned())
            .unwrap()
    };

    let body = test::read_body(resp).await;
    let token = String::from_utf8(body.to_vec()).unwrap();
    let token = token.strip_prefix("token:").unwrap().to_string();

    (token, token_cookie, session_id_cookie)
}

#[actix_web::test]
async fn test_double_submit_cookie_behavior() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (initial_token, initial_token_cookie, session_id_cookie) =
        token_cookie(&app, None, None).await;

    // Verify no token change on a non-mutating GET
    let req = test::TestRequest::get()
        .uri("/form")
        .cookie(initial_token_cookie.clone())
        .cookie(session_id_cookie.clone())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Check that the cookie wasn't changed in the response
    let token_cookie_after_get = resp
        .response()
        .cookies()
        .find(|c| c.name() == DEFAULT_CSRF_TOKEN_KEY);

    // If there's no new cookie set, the token remains the same
    assert!(
        token_cookie_after_get.is_none(),
        "Token cookie should not be set on GET request when token already exists"
    );

    // Verify token change on a mutating POST
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, initial_token.clone()))
        .cookie(initial_token_cookie)
        .cookie(session_id_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Check that a new cookie was set in the response after mutation
    let new_token_cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == DEFAULT_CSRF_TOKEN_KEY || c.name() == DEFAULT_CSRF_ANON_TOKEN_KEY)
        .expect("New token cookie should be set after POST mutation");

    let new_token = new_token_cookie.value();
    assert_ne!(
        initial_token, new_token,
        "Token should refresh on POST mutation"
    );
}

#[actix_web::test]
async fn double_submit_cookie_token_rotation() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (initial_token, initial_token_cookie, initial_session_cookie) =
        token_cookie(&app, None, None).await;

    // Perform a POST request with the initial token
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, initial_token.clone()))
        .cookie(initial_token_cookie)
        .cookie(initial_session_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Get a new token after the mutation
    let (new_token, _new_token_cookie, _new_session_id_cookie) =
        token_cookie(&app, None, None).await;
    assert_ne!(
        initial_token, new_token,
        "CSRF token should be refreshed after mutation"
    );

    // Verify the new token is still in correct HMAC format
    assert!(
        new_token.contains('.'),
        "New token should maintain HMAC format"
    );
    let parts: Vec<&str> = new_token.split('.').collect();
    assert_eq!(
        parts.len(),
        2,
        "New token should have HMAC format with 2 parts"
    );
}

#[actix_web::test]
async fn instant_rotation_on_login() {
    use actix_web::cookie::{time, Cookie};

    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;

    // Initial anonymous token
    let (_anon_token, anon_token_cookie, pre_session_cookie) = token_cookie(&app, None, None).await;

    // Simulate login by sending a GET with a fresh session id cookie while still having anon cookie
    let session_cookie = Cookie::build(DEFAULT_SESSION_ID_KEY, "SID-123").finish();

    let req = test::TestRequest::get()
        .uri("/form")
        .cookie(anon_token_cookie.clone())
        .cookie(pre_session_cookie.clone())
        .cookie(session_cookie)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Expect pre-session to be expired and a new CSRF cookie to be set
    let mut saw_expired_pre_session = false;
    let mut saw_new_auth = false;

    for c in resp.response().cookies() {
        if c.name() == CSRF_PRE_SESSION_KEY {
            // Should be expired (Max-Age=0)
            if let Some(ma) = c.max_age() {
                assert_eq!(
                    ma,
                    time::Duration::seconds(0),
                    "pre-session cookie should be expired"
                );
                saw_expired_pre_session = true;
            }
        }

        if c.name() == DEFAULT_CSRF_TOKEN_KEY {
            assert!(!c.value().is_empty(), "new authorized token must be set");
            saw_new_auth = true;
        }
    }

    assert!(
        saw_expired_pre_session,
        "Expected pre-session cookie to be expired after login"
    );
    assert!(saw_new_auth, "Expected new CSRF token after login");
}

#[actix_web::test]
async fn authorized_endpoint_rejects_anon_token() {
    use actix_web::cookie::Cookie;

    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;

    // Anonymous context first: get anon token and cookies
    let (anon_token, anon_token_cookie, pre_session_cookie) = token_cookie(&app, None, None).await;

    // Now simulate an authorized POST using the anon token (should be rejected)
    let session_cookie = Cookie::build(DEFAULT_SESSION_ID_KEY, "SID-456").finish();

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, anon_token))
        .cookie(anon_token_cookie)
        .cookie(pre_session_cookie)
        .cookie(session_cookie)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "anon token must not be accepted on authorized endpoints"
    );
}

#[actix_web::test]
async fn token_refresh_on_successful_mutation() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (token1, token1_cookie, session1_cookie) = { token_cookie(&app, None, None).await };

    // POST with valid token
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, token1.clone()))
        .cookie(token1_cookie)
        .cookie(session1_cookie)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // GET new token (should be refreshed)
    let (new_token, _token_cookie, _session_id_cookie) = { token_cookie(&app, None, None).await };
    assert_ne!(token1, new_token, "Token should be refreshed after POST");
}

#[actix_web::test]
async fn custom_config_header_name() {
    const HEADER_NAME: &str = "custom-header";

    let cfg = CsrfMiddlewareConfig {
        pattern: CsrfPattern::DoubleSubmitCookie,
        manual_multipart: false,
        session_id_cookie_name: DEFAULT_SESSION_ID_KEY.to_string(),
        token_cookie_name: DEFAULT_CSRF_TOKEN_KEY.to_string(),
        anon_token_cookie_name: DEFAULT_CSRF_ANON_TOKEN_KEY.to_string(),
        token_form_field: "myfield".to_string(),
        token_header_name: HEADER_NAME.to_string(),
        #[cfg(feature = "actix-session")]
        anon_session_key_name: format!("{}-anon", DEFAULT_CSRF_TOKEN_KEY),
        token_cookie_config: Some(CsrfDoubleSubmitCookie {
            http_only: false,
            secure: true,
            same_site: SameSite::Lax,
        }),
        secret_key: get_secret_key().into(),
        skip_for: vec![],
        enforce_origin: false,
        allowed_origins: vec![],
        max_body_bytes: 2 * 1024 * 1024,
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
        manual_multipart: false,
        session_id_cookie_name: DEFAULT_SESSION_ID_KEY.to_string(),
        token_cookie_name: COOKIE_NAME.to_string(),
        anon_token_cookie_name: DEFAULT_CSRF_ANON_TOKEN_KEY.to_string(),
        token_form_field: DEFAULT_CSRF_TOKEN_FIELD.to_string(),
        token_header_name: DEFAULT_CSRF_TOKEN_HEADER.to_string(),
        #[cfg(feature = "actix-session")]
        anon_session_key_name: format!("{}-anon", DEFAULT_CSRF_TOKEN_KEY),
        token_cookie_config: Some(CsrfDoubleSubmitCookie {
            http_only: false,
            secure: true,
            same_site: SameSite::Lax,
        }),
        secret_key: get_secret_key().into(),
        skip_for: vec![],
        enforce_origin: false,
        allowed_origins: vec![],
        max_body_bytes: 2 * 1024 * 1024,
    };
    let app = build_app(cfg).await;
    let (token, token_cookie, session_id_cookie) =
        { token_cookie(&app, None, Some(COOKIE_NAME)).await };

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, token))
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
        manual_multipart: false,
        session_id_cookie_name: DEFAULT_SESSION_ID_KEY.to_string(),
        token_cookie_name: DEFAULT_CSRF_TOKEN_KEY.to_string(),
        anon_token_cookie_name: DEFAULT_CSRF_ANON_TOKEN_KEY.to_string(),
        token_form_field: FIELD_NAME.to_string(),
        token_header_name: "myheader".to_string(),
        #[cfg(feature = "actix-session")]
        anon_session_key_name: format!("{}-anon", DEFAULT_CSRF_TOKEN_KEY),
        token_cookie_config: Some(CsrfDoubleSubmitCookie {
            http_only: false,
            secure: true,
            same_site: SameSite::Lax,
        }),
        secret_key: get_secret_key().into(),
        skip_for: vec![],
        enforce_origin: false,
        allowed_origins: vec![],
        max_body_bytes: 2 * 1024 * 1024,
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
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, token))
        .insert_header(ContentType::form_url_encoded())
        .cookie(token_cookie)
        .cookie(session_id_cookie)
        .set_payload(large)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
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
    assert!(
        resp.status().is_client_error(),
        "malformed json body cannot be passed"
    )
}

#[actix_web::test]
async fn token_should_be_unforgeable() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, _session_cookie) = token_cookie(&app, None, None).await;

    let tok = generate_random_token();
    let mut mac = HmacSha256::new_from_slice(HMAC_SECRET).expect("HMAC can take key of any size");
    let message = format!("auth|HOW-TO-GET-SESSION-ID?=)|{tok}");
    mac.update(message.as_bytes());

    let hmac_hex = hex::encode(mac.finalize().into_bytes());
    let forged_token = format!("{hmac_hex}.{tok}");

    let req = test::TestRequest::post()
        .uri("/submit")
        .cookie(token_cookie)
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, forged_token))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
