#[macro_use]
mod common;

use actix_csrf_middleware::{CsrfPattern, DEFAULT_CSRF_TOKEN_HEADER};
use actix_http::body::{BoxBody, EitherBody};
use actix_http::Request;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::test;

use common::*;

fn get_secret_key() -> Vec<u8> {
    b"super-secret-super-secret-super-secret-xx".to_vec()
}

async fn case_method_override_bypass<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (_token, cookies) = token_and_cookies_for(app, &pattern).await;
    let mut req = test::TestRequest::get()
        .uri("/submit_get")
        .insert_header(("X-HTTP-Method-Override", "POST"));

    for c in cookies {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert!(resp.status().is_success());
}

async fn case_token_endpoint_access_control<S>(_pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    for _ in 0..50 {
        let req = test::TestRequest::get().uri("/form").to_request();
        let resp = test::call_service(app, req).await;
        assert!(resp.status().is_success());
    }
}

async fn case_privilege_escalation_attempt<S>(pattern: CsrfPattern, app: &S)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let (token1, _cookies1) = token_and_cookies_for(app, &pattern).await;
    let (_token2, cookies2) = token_and_cookies_for(app, &pattern).await;
    let mut req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, token1));

    for c in cookies2 {
        req = req.cookie(c);
    }

    let resp = test::call_service(app, req.to_request()).await;
    assert_eq!(resp.status(), 400);
}

for_patterns!(
    a01_method_override_double,
    a01_method_override_sync,
    case_method_override_bypass
);
for_patterns!(
    a01_token_endpoint_access_double,
    a01_token_endpoint_access_sync,
    case_token_endpoint_access_control
);
for_patterns!(
    a01_privilege_escalation_double,
    a01_privilege_escalation_sync,
    case_privilege_escalation_attempt
);
