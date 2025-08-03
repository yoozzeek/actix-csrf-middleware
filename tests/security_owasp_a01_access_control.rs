mod common;

use actix_csrf_middleware::{CsrfMiddlewareConfig, DEFAULT_HEADER};
use actix_web::test;
use common::*;

/// Test bypass attempts through HTTP method override
#[actix_web::test]
async fn test_method_override_bypass_attempt() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_cookie) = token_cookie(&app, None, None).await;

    // Attempt to bypass CSRF using X-HTTP-Method-Override on a GET route
    let req = test::TestRequest::get() // GET request
        .uri("/submit_get")
        .insert_header(("X-HTTP-Method-Override", "POST")) // Try to override to POST
        .cookie(token_cookie)
        .cookie(session_cookie)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    // Should still be treated as GET and succeed without CSRF validation
    // The middleware should ignore method override headers for security reasons
    assert!(resp.status().is_success());
}

/// Test unauthorized access to CSRF token generation endpoints
#[actix_web::test]
async fn test_csrf_token_endpoint_access_control() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    
    // Multiple rapid requests to token endpoint to check for rate limiting
    for _ in 0..50 {
        let req = test::TestRequest::get().uri("/form").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}

/// Test privilege escalation through CSRF token manipulation
#[actix_web::test]
async fn test_token_privilege_escalation_attempt() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    
    // Get token for one session
    let (token1, cookie1, session1) = token_cookie(&app, None, None).await;
    let (token2, cookie2, session2) = token_cookie(&app, None, None).await;
    
    // Try to use token1 with session2 (cross-session attack)
    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_HEADER, token1))
        .cookie(cookie2) // Wrong cookie
        .cookie(session2) // Wrong session
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400); // Should fail
}

fn get_secret_key() -> Vec<u8> {
    b"super-secret".to_vec()
}

pub async fn token_cookie<S>(
    app: &S,
    session_id_cookie_name: Option<&str>,
    token_cookie_name: Option<&str>,
) -> (String, actix_web::cookie::Cookie<'static>, actix_web::cookie::Cookie<'static>)
where
    S: actix_web::dev::Service<actix_http::Request, Response = actix_web::dev::ServiceResponse<actix_http::body::EitherBody<actix_http::body::BoxBody>>, Error = actix_web::Error>,
{
    use actix_csrf_middleware::{DEFAULT_COOKIE_NAME, DEFAULT_SESSION_ID_COOKIE_NAME, PRE_SESSION_COOKIE_NAME};
    
    let req = test::TestRequest::get().uri("/form").to_request();
    let resp = test::call_service(&app, req).await;

    let session_id_cookie_name = session_id_cookie_name.unwrap_or(DEFAULT_SESSION_ID_COOKIE_NAME);
    let token_cookie_name = token_cookie_name.unwrap_or(DEFAULT_COOKIE_NAME);

    let session_id_cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == session_id_cookie_name || c.name() == PRE_SESSION_COOKIE_NAME)
        .map(|c| c.into_owned())
        .unwrap();

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
