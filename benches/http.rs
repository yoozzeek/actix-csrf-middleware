use actix_csrf_middleware::{
    CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken, DEFAULT_COOKIE_NAME, DEFAULT_HEADER,
};
#[cfg(feature = "actix-session")]
use actix_session::{
    SessionMiddleware, config::CookieContentSecurity, storage::CookieSessionStore,
};
use actix_web::cookie::{Key, SameSite};
use actix_web::{App, HttpResponse, test, web};
use std::time::Instant;

fn test_key() -> Key {
    Key::generate()
}

fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/form",
        web::get().to(|csrf: CsrfToken| async move {
            HttpResponse::Ok().body(format!("token:{}", csrf.0))
        }),
    )
    .route(
        "/submit",
        web::post().to(|_csrf: CsrfToken| async move { HttpResponse::Ok().body("OK") }),
    );
}

#[cfg(feature = "actix-session")]
fn get_session_middleware() -> SessionMiddleware<CookieSessionStore> {
    SessionMiddleware::builder(CookieSessionStore::default(), test_key())
        .cookie_content_security(CookieContentSecurity::Private)
        .cookie_secure(true)
        .cookie_http_only(true)
        .cookie_same_site(SameSite::Strict)
        .build()
}

#[actix_rt::main]
async fn main() {
    let cfg = CsrfMiddlewareConfig::default();
    let app = test::init_service({
        let app = App::new().wrap(CsrfMiddleware::new(cfg));
        #[cfg(feature = "actix-session")]
        let app = app.wrap(get_session_middleware());
        app.configure(configure_routes)
    })
    .await;

    let iterations = 100000;
    let start = Instant::now();

    for _ in 0..iterations {
        // 1. GET /form
        let req = test::TestRequest::get().uri("/form").to_request();
        let resp = test::call_service(&app, req).await;

        let target_cookie_name = if cfg!(feature = "actix-session") {
            "id"
        } else {
            DEFAULT_COOKIE_NAME
        };
        let cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == target_cookie_name)
            .map(|c| c.into_owned())
            .unwrap();
        let body = test::read_body(resp).await;
        let token = String::from_utf8(body.to_vec()).unwrap();
        let token = token.strip_prefix("token:").unwrap();

        // 2. POST /submit
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_HEADER, token))
            .cookie(cookie)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    let elapsed = start.elapsed();
    println!("{} iterations took: {:?}", iterations, elapsed);
    println!(
        "Avg per flow: {:.3}us",
        elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64
    );
}
