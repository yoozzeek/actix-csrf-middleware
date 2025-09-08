#[macro_use]
mod common;

use actix_csrf_middleware::{
    CsrfMiddlewareConfig, CsrfPattern, CSRF_PRE_SESSION_KEY, DEFAULT_CSRF_ANON_TOKEN_KEY,
    DEFAULT_CSRF_TOKEN_HEADER, DEFAULT_CSRF_TOKEN_KEY, DEFAULT_SESSION_ID_KEY,
};
use actix_http::body::{BoxBody, EitherBody};
use actix_http::Request;
use actix_web::cookie::Cookie;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::test;
use common::*;

fn get_secret_key() -> Vec<u8> {
    b"super-secret".to_vec()
}

fn config_for(pattern: CsrfPattern) -> CsrfMiddlewareConfig {
    match pattern {
        #[cfg(feature = "actix-session")]
        CsrfPattern::SynchronizerToken => {
            CsrfMiddlewareConfig::synchronizer_token(&get_secret_key())
        }
        CsrfPattern::DoubleSubmitCookie => {
            CsrfMiddlewareConfig::double_submit_cookie(&get_secret_key())
        }
    }
}

async fn token_and_cookies_for<S>(app: &S, pattern: &CsrfPattern) -> (String, Vec<Cookie<'static>>)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    match pattern {
        CsrfPattern::DoubleSubmitCookie => {
            let req = test::TestRequest::get().uri("/form").to_request();
            let resp = test::call_service(&app, req).await;
            let token_cookie = resp
                .response()
                .cookies()
                .find(|c| {
                    c.name() == DEFAULT_CSRF_TOKEN_KEY || c.name() == DEFAULT_CSRF_ANON_TOKEN_KEY
                })
                .map(|c| c.into_owned())
                .expect("token cookie present");
            let session_cookie = resp
                .response()
                .cookies()
                .find(|c| c.name() == DEFAULT_SESSION_ID_KEY || c.name() == CSRF_PRE_SESSION_KEY)
                .map(|c| c.into_owned())
                .expect("session/pre-session cookie present");
            let body = test::read_body(resp).await;
            let token = String::from_utf8(body.to_vec()).unwrap();
            let token = token.strip_prefix("token:").unwrap().to_string();
            (token, vec![token_cookie, session_cookie])
        }
        #[cfg(feature = "actix-session")]
        CsrfPattern::SynchronizerToken => {
            let req1 = test::TestRequest::get().uri("/form").to_request();
            let resp1 = test::call_service(&app, req1).await;
            let session_cookie = resp1
                .response()
                .cookies()
                .find(|c| c.name() == DEFAULT_SESSION_ID_KEY)
                .map(|c| c.into_owned())
                .expect("session cookie present");
            let req2 = test::TestRequest::get()
                .uri("/form")
                .cookie(session_cookie.clone())
                .to_request();
            let resp2 = test::call_service(&app, req2).await;
            let session_cookie2 = resp2
                .response()
                .cookies()
                .find(|c| c.name() == DEFAULT_SESSION_ID_KEY)
                .map(|c| c.into_owned())
                .unwrap_or_else(|| session_cookie.clone());
            let body2 = test::read_body(resp2).await;
            let token2 = String::from_utf8(body2.to_vec()).unwrap();
            let token2 = token2.strip_prefix("token:").unwrap().to_string();
            (token2, vec![session_cookie2])
        }
    }
}

macro_rules! for_patterns {
    ($name_double:ident, $name_sync:ident, $body:expr) => {
        #[actix_web::test]
        async fn $name_double() {
            let cfg = config_for(CsrfPattern::DoubleSubmitCookie);
            let app = build_app(cfg).await;
            $body(CsrfPattern::DoubleSubmitCookie, &app).await;
        }
        #[cfg(feature = "actix-session")]
        #[actix_web::test]
        async fn $name_sync() {
            let cfg = config_for(CsrfPattern::SynchronizerToken);
            let app = build_app(cfg).await;
            $body(CsrfPattern::SynchronizerToken, &app).await;
        }
    };
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
