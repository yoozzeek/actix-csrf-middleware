mod common;

use actix_csrf_middleware::{
    generate_hmac_token_ctx, validate_hmac_token, CsrfMiddlewareConfig, TokenClass,
    DEFAULT_CSRF_ANON_TOKEN_KEY, DEFAULT_CSRF_TOKEN_HEADER,
};
use actix_web::{http::StatusCode, test};
use common::*;

#[actix_web::test]
async fn test_weak_secret_key_detection() {
    // Extremely weak secret key must cause constructor to panic
    let result = std::panic::catch_unwind(|| {
        let _ = CsrfMiddlewareConfig::double_submit_cookie(b"1");
    });
    assert!(
        result.is_err(),
        "config constructor must panic on short secret"
    );
}

/// Test for predictable token generation
#[actix_web::test]
async fn test_token_entropy_analysis() {
    use std::collections::HashSet;

    let secret_key = b"test-secret-key-for-entropy-test".to_vec();

    // Generate multiple tokens and check for patterns
    let mut tokens = HashSet::new();
    for _ in 0..1000 {
        let token = generate_hmac_token_ctx(TokenClass::Authorized, "session_id", &secret_key);
        tokens.insert(token);
    }

    // All tokens should be unique (high entropy)
    assert_eq!(
        tokens.len(),
        1000,
        "Tokens should be unique - potential entropy issue"
    );
}

/// Test HMAC timing attack resistance
#[actix_web::test]
async fn test_hmac_timing_attack_resistance() {
    let secret_key = b"timing-attack-test-secret".to_vec();
    let session_id = "test_session";

    let valid_token = generate_hmac_token_ctx(TokenClass::Authorized, session_id, &secret_key);

    // Test multiple invalid tokens with same prefix (timing attack attempt)
    let invalid_tokens = vec![
        "invalid_token_1",
        "invalid_token_2",
        "invalid_token_with_longer_name",
        &valid_token[..10], // Partial valid token
    ];

    for invalid_token in invalid_tokens {
        let result = validate_hmac_token(session_id, invalid_token.as_bytes(), &secret_key);
        if let Ok(is_valid) = result {
            assert!(!is_valid, "Invalid token should not validate");
        }
    }
}

/// Test key reuse across different contexts
#[actix_web::test]
async fn test_key_reuse_vulnerability() {
    let shared_secret = b"shared-secret-key".to_vec();

    // Simulate two different applications using the same key
    let token1 = generate_hmac_token_ctx(TokenClass::Authorized, "app1_session", &shared_secret);
    let token2 = generate_hmac_token_ctx(TokenClass::Authorized, "app2_session", &shared_secret);

    // Tokens should be different even with same key
    assert_ne!(
        token1, token2,
        "Different sessions should generate different tokens"
    );

    // Cross-validation should fail
    let cross_validation = validate_hmac_token("app1_session", token2.as_bytes(), &shared_secret);
    assert!(
        !cross_validation.unwrap_or(true),
        "Cross-session validation should fail"
    );
}

/// Test for token format disclosure
#[actix_web::test]
async fn test_token_format_information_disclosure() {
    let secret_key = b"format-test-secret".to_vec();
    let session_id = "format_test_session";

    let token = generate_hmac_token_ctx(TokenClass::Authorized, session_id, &secret_key);

    // Token should follow expected format: hmac.random_part
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(
        parts.len(),
        2,
        "Token should have exactly 2 parts separated by '.'"
    );

    // HMAC part should be hex encoded (64 characters for SHA256)
    assert_eq!(parts[0].len(), 64, "HMAC part should be 64 hex characters");

    // Verify hex encoding
    assert!(
        hex::decode(parts[0]).is_ok(),
        "HMAC part should be valid hex"
    );
}

/// Test empty or null secret key handling for pure HMAC helpers (allowed)
#[actix_web::test]
async fn test_empty_secret_key_handling() {
    let empty_key = b"";
    let session_id = "test_session";

    // Pure helper must operate (we enforce secret length only at middleware config level)
    let token = generate_hmac_token_ctx(TokenClass::Authorized, session_id, empty_key);
    let validation = validate_hmac_token(session_id, token.as_bytes(), empty_key);

    assert!(validation.unwrap_or(false));
}

/// Test malformed token injection attempts
#[actix_web::test]
async fn test_malformed_token_injection() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_cookie) = token_cookie(&app, None, None).await;

    let malformed_tokens = vec![
        "...", // Multiple dots
        "no_dot_separator",
        "",                           // Empty token
        "onlyhmac.",                  // Missing random part
        ".onlyrandom",                // Missing HMAC
        "invalid.hex.too.many.parts", // Too many parts
        "nonhex!@#$.validrandom",     // Invalid hex in HMAC
    ];

    for malformed_token in malformed_tokens {
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_CSRF_TOKEN_HEADER, malformed_token))
            .cookie(token_cookie.clone())
            .cookie(session_cookie.clone())
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Malformed token '{malformed_token}' should be rejected"
        );
    }
}

fn get_secret_key() -> Vec<u8> {
    b"crypto-failures-secret-32bytes-minimum-xx".to_vec()
}

pub async fn token_cookie<S>(
    app: &S,
    session_id_cookie_name: Option<&str>,
    token_cookie_name: Option<&str>,
) -> (
    String,
    actix_web::cookie::Cookie<'static>,
    actix_web::cookie::Cookie<'static>,
)
where
    S: actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<
            actix_http::body::EitherBody<actix_http::body::BoxBody>,
        >,
        Error = actix_web::Error,
    >,
{
    use actix_csrf_middleware::{
        CSRF_PRE_SESSION_KEY, DEFAULT_CSRF_TOKEN_KEY, DEFAULT_SESSION_ID_KEY,
    };

    let req = test::TestRequest::get().uri("/form").to_request();
    let resp = test::call_service(&app, req).await;

    let session_id_cookie_name = session_id_cookie_name.unwrap_or(DEFAULT_SESSION_ID_KEY);
    let token_cookie_name = token_cookie_name.unwrap_or(DEFAULT_CSRF_TOKEN_KEY);

    let session_id_cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == session_id_cookie_name || c.name() == CSRF_PRE_SESSION_KEY)
        .map(|c| c.into_owned())
        .unwrap();

    // Prefer authorized cookie name; if not present (anon flow), fall back to anon cookie name
    let token_cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == token_cookie_name || c.name() == DEFAULT_CSRF_ANON_TOKEN_KEY)
        .map(|c| c.into_owned())
        .unwrap();

    let body = test::read_body(resp).await;
    let token = String::from_utf8(body.to_vec()).unwrap();
    let token = token.strip_prefix("token:").unwrap().to_string();

    (token, token_cookie, session_id_cookie)
}
