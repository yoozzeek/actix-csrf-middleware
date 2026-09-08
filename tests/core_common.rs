#[macro_use]
mod common;

use actix_csrf_middleware::{CsrfPattern, DEFAULT_CSRF_TOKEN_HEADER, MultipartRoute};
use actix_http::Request;
use actix_http::body::{BoxBody, EitherBody};
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::header::ContentType;
use actix_web::test;
use actix_web::web::Bytes;
use common::token_and_cookies_for;
use serde_json::json;

const MULTIPART_BOUNDARY: &str = "----parametric-boundary";

fn get_secret_key() -> Vec<u8> {
    b"param-secret-param-secret-param-secret-1234".to_vec()
}

async fn case_valid_header<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token, cookies) = token_and_cookies_for(app, &pattern).await;
    let mut req = test::TestRequest::post().uri("/submit");
    req = req.insert_header((DEFAULT_CSRF_TOKEN_HEADER, token));

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert!(resp.status().is_success());
}

async fn case_missing_token<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let mut req = test::TestRequest::post().uri("/submit");

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert_eq!(resp.status(), 400);
}

async fn case_invalid_header<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let mut req = test::TestRequest::post().uri("/submit");
    req = req.insert_header((DEFAULT_CSRF_TOKEN_HEADER, "wrong-token"));

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert_eq!(resp.status(), 400);
}

async fn case_valid_form<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token, cookies) = token_and_cookies_for(app, &pattern).await;
    let form = format!("csrf_token={token}");
    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::form_url_encoded())
        .set_payload(form);

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert!(resp.status().is_success());
}

async fn case_invalid_form<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let form = "csrf_token=wrong-token";
    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::form_url_encoded())
        .set_payload(form);

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert_eq!(resp.status(), 400);
}

async fn case_valid_json<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token, cookies) = token_and_cookies_for(app, &pattern).await;
    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .set_json(json!({"csrf_token": token}));

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert!(resp.status().is_success());
}

async fn case_invalid_json<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .set_json(json!({"csrf_token": "wrong-token"}));

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert_eq!(resp.status(), 400);
}

// Rotation after successful POST should refresh token
async fn case_rotation_after_post<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token1, cookies1) = token_and_cookies_for(app, &pattern).await;
    // POST with valid header token
    let mut req = test::TestRequest::post().uri("/submit");
    req = req.insert_header((DEFAULT_CSRF_TOKEN_HEADER, token1.clone()));
    for c in cookies1.clone() {
        req = req.cookie(c);
    }
    let resp = test::call_service(app, req.to_request()).await;
    assert!(resp.status().is_success());

    // Fetch new token
    let (token2, _cookies2) = token_and_cookies_for(app, &pattern).await;
    assert_ne!(token1, token2, "token should rotate after POST");
}

// Multipart disabled should reject multipart/form-data
async fn case_multipart_disabled<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token, cookies) = token_and_cookies_for(app, &pattern).await;

    // Create multipart body including token field
    let boundary = "----parametric-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n");
    body.extend_from_slice(token.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        ))
        .set_payload(Bytes::from(body));
    for c in cookies {
        req = req.cookie(c);
    }
    let resp = test::call_service(app, req.to_request()).await;
    assert_eq!(resp.status(), 400, "multipart disabled should reject");
}

async fn case_multipart_listed_path_passes_through<S>(pattern: CsrfPattern, _app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let cfg = common::config_for_with_secret(pattern.clone(), &get_secret_key())
        .with_multipart(vec![MultipartRoute::Exact("/submit".to_owned())]);
    let app = common::build_app(cfg).await;
    let (_token, cookies) = token_and_cookies_for(&app, &pattern).await;

    let mut req = multipart_upload_to("/submit");

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(&app, req.to_request()).await;
    assert!(
        resp.status().is_success(),
        "a listed path reaches the handler without a middleware token check"
    );
}

async fn case_multipart_unlisted_path_rejected<S>(pattern: CsrfPattern, _app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let cfg = common::config_for_with_secret(pattern.clone(), &get_secret_key())
        .with_multipart(vec![MultipartRoute::Exact("/some-other-upload".to_owned())]);
    let app = common::build_app(cfg).await;
    let (_token, cookies) = token_and_cookies_for(&app, &pattern).await;

    let mut req = multipart_upload_to("/submit");

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(&app, req.to_request()).await;
    assert_eq!(
        resp.status(),
        400,
        "exempting one path must not exempt every other route from the token check"
    );
}

async fn case_multipart_exemption_keeps_origin_enforced<S>(pattern: CsrfPattern, _app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let cfg = common::config_for_with_secret(pattern.clone(), &get_secret_key())
        .with_multipart(vec![MultipartRoute::Exact("/submit".to_owned())])
        .with_enforce_origin(true, vec!["https://allowed.example".to_owned()]);
    let app = common::build_app(cfg).await;
    let (_token, cookies) = token_and_cookies_for(&app, &pattern).await;

    let mut req = multipart_upload_to("/submit").insert_header(("Origin", "https://evil.example"));

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(&app, req.to_request()).await;
    assert_eq!(
        resp.status(),
        403,
        "a multipart exemption must not bypass Origin enforcement"
    );
}

// Custom header success
async fn case_custom_header_success<S>(pattern: CsrfPattern, _app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    const HEADER_NAME: &str = "X-Custom-Header";

    let mut cfg = common::config_for_with_secret(pattern.clone(), &get_secret_key());
    cfg.token_header_name = HEADER_NAME.to_string();
    let app = common::build_app(cfg).await;
    let (token, cookies) = token_and_cookies_for(&app, &pattern).await;

    let mut req = test::TestRequest::post().uri("/submit");
    req = req.insert_header((HEADER_NAME, token));

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(&app, req.to_request()).await;
    assert!(resp.status().is_success());
}

// Custom form field success
async fn case_custom_form_success<S>(pattern: CsrfPattern, _app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    const FIELD_NAME: &str = "csrf_custom";

    let mut cfg = common::config_for_with_secret(pattern.clone(), &get_secret_key());
    cfg.token_form_field = FIELD_NAME.to_string();

    let app = common::build_app(cfg).await;
    let (token, cookies) = token_and_cookies_for(&app, &pattern).await;

    let form = format!("{FIELD_NAME}={token}");
    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::form_url_encoded())
        .set_payload(form);

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(&app, req.to_request()).await;
    assert!(resp.status().is_success());
}

// Token format checks per pattern
async fn case_token_format<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token, _cookies) = token_and_cookies_for(app, &pattern).await;
    match pattern {
        CsrfPattern::DoubleSubmitCookie => {
            assert!(token.contains('.'), "HMAC token must contain dot separator");

            let parts: Vec<&str> = token.split('.').collect();
            assert_eq!(parts.len(), 2, "HMAC token must have 2 parts");

            let (hmac_hex, csrf_token) = (parts[0], parts[1]);
            assert_eq!(hmac_hex.len(), 64, "HMAC hex must be 64 chars (sha256)");
            assert!(hmac_hex.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(
                csrf_token.len(),
                43,
                "random part must be 43 chars (32B b64url)"
            );
            assert!(
                csrf_token
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            );
        }
        #[cfg(feature = "actix-session")]
        CsrfPattern::SynchronizerToken => {
            assert_eq!(
                token.len(),
                43,
                "synchronizer token is 32B b64url (43 chars)"
            );
            assert!(
                !token.contains('.'),
                "synchronizer token must not contain dot"
            );
            assert!(
                token
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            );
        }
    }
}

// Token uniqueness across fresh sessions
async fn case_token_uniqueness<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    use std::collections::HashSet;
    const N: usize = 100;
    let mut set = HashSet::new();

    for _ in 0..N {
        let (tok, _cookies) = token_and_cookies_for(app, &pattern).await;
        set.insert(tok);
    }

    assert_eq!(set.len(), N, "tokens must be unique across fresh sessions");
}

async fn case_json_token_after_escaped_key<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token, cookies) = token_and_cookies_for(app, &pattern).await;
    let body = format!(r#"{{"a\"b":{{"nested":[1,2]}},"csrf_token":"{token}"}}"#);

    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .set_payload(body);

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert!(
        resp.status().is_success(),
        "an escaped key must not hide the token"
    );
}

async fn case_json_duplicate_token_field_takes_last<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token, cookies) = token_and_cookies_for(app, &pattern).await;
    let body = format!(r#"{{"csrf_token":"decoy","csrf_token":"{token}"}}"#);

    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .set_payload(body);

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert!(resp.status().is_success());
}

async fn case_json_mixed_type_duplicate_rejected<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token, cookies) = token_and_cookies_for(app, &pattern).await;
    let body = format!(r#"{{"csrf_token":123,"csrf_token":"{token}"}}"#);

    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .set_payload(body);

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert_eq!(
        resp.status(),
        400,
        "a non-string occurrence must fail closed"
    );
}

async fn case_json_trailing_content_rejected<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token, cookies) = token_and_cookies_for(app, &pattern).await;
    let body = format!(r#"{{"csrf_token":"{token}"}} trailing"#);

    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .set_payload(body);

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert_eq!(
        resp.status(),
        400,
        "a token must not be read out of a malformed document"
    );
}

async fn case_json_non_object_body_rejected<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token, cookies) = token_and_cookies_for(app, &pattern).await;
    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .set_payload(format!(r#"["{token}"]"#));

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert_eq!(resp.status(), 400);
}

async fn case_json_non_string_token_rejected<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::json())
        .set_payload(r#"{"csrf_token":12345}"#);

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert_eq!(resp.status(), 400);
}

async fn case_form_percent_encoded_token<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token, cookies) = token_and_cookies_for(app, &pattern).await;
    let encoded = token.replace('.', "%2E");
    let form = format!("other=a%20b&csrf_token={encoded}");

    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header(ContentType::form_url_encoded())
        .set_payload(form);

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert!(
        resp.status().is_success(),
        "percent-encoded token must decode"
    );
}

fn multipart_upload_to(uri: &str) -> test::TestRequest {
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{MULTIPART_BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n\r\n");
    body.extend_from_slice(b"data");
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{MULTIPART_BOUNDARY}--\r\n").as_bytes());

    test::TestRequest::post()
        .uri(uri)
        .insert_header((
            "Content-Type",
            format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}"),
        ))
        .set_payload(Bytes::from(body))
}

for_patterns!(
    param_valid_header_double,
    param_valid_header_sync,
    case_valid_header
);
for_patterns!(
    param_missing_token_double,
    param_missing_token_sync,
    case_missing_token
);
for_patterns!(
    param_invalid_header_double,
    param_invalid_header_sync,
    case_invalid_header
);
for_patterns!(
    param_valid_form_double,
    param_valid_form_sync,
    case_valid_form
);
for_patterns!(
    param_invalid_form_double,
    param_invalid_form_sync,
    case_invalid_form
);
for_patterns!(
    param_valid_json_double,
    param_valid_json_sync,
    case_valid_json
);
for_patterns!(
    param_invalid_json_double,
    param_invalid_json_sync,
    case_invalid_json
);
for_patterns!(
    param_rotation_double,
    param_rotation_sync,
    case_rotation_after_post
);
for_patterns!(
    param_multipart_disabled_double,
    param_multipart_disabled_sync,
    case_multipart_disabled
);
for_patterns!(
    param_multipart_enabled_double,
    param_multipart_enabled_sync,
    case_multipart_listed_path_passes_through
);
for_patterns!(
    param_multipart_unlisted_double,
    param_multipart_unlisted_sync,
    case_multipart_unlisted_path_rejected
);
for_patterns!(
    param_multipart_origin_double,
    param_multipart_origin_sync,
    case_multipart_exemption_keeps_origin_enforced
);
for_patterns!(
    param_custom_header_double,
    param_custom_header_sync,
    case_custom_header_success
);
for_patterns!(
    param_custom_form_double,
    param_custom_form_sync,
    case_custom_form_success
);
for_patterns!(
    param_token_format_double,
    param_token_format_sync,
    case_token_format
);
for_patterns!(
    param_token_uniqueness_double,
    param_token_uniqueness_sync,
    case_token_uniqueness
);
for_patterns!(
    param_json_escaped_key_double,
    param_json_escaped_key_sync,
    case_json_token_after_escaped_key
);
for_patterns!(
    param_json_duplicate_field_double,
    param_json_duplicate_field_sync,
    case_json_duplicate_token_field_takes_last
);
for_patterns!(
    param_json_mixed_type_duplicate_double,
    param_json_mixed_type_duplicate_sync,
    case_json_mixed_type_duplicate_rejected
);
for_patterns!(
    param_json_trailing_content_double,
    param_json_trailing_content_sync,
    case_json_trailing_content_rejected
);
for_patterns!(
    param_json_non_object_double,
    param_json_non_object_sync,
    case_json_non_object_body_rejected
);
for_patterns!(
    param_json_non_string_double,
    param_json_non_string_sync,
    case_json_non_string_token_rejected
);
for_patterns!(
    param_form_encoded_token_double,
    param_form_encoded_token_sync,
    case_form_percent_encoded_token
);
