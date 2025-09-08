use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken, DEFAULT_SESSION_ID_KEY};
use actix_session::{config::CookieContentSecurity, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::{Key, SameSite}, web, App, HttpResponse, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Example-only secret. Do not use in production.
    let secret = b"example-secret-key-please-change-32+bytes";

    let csrf_config = CsrfMiddlewareConfig::synchronizer_token(secret);

    HttpServer::new(move || {
        App::new()
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), Key::generate())
                    .cookie_content_security(CookieContentSecurity::Private)
                    .cookie_name(DEFAULT_SESSION_ID_KEY.to_string())
                    .cookie_secure(false) // for local demo only
                    .cookie_http_only(true)
                    .cookie_same_site(SameSite::Lax)
                    .build(),
            )
            .wrap(CsrfMiddleware::new(csrf_config.clone()))
            // Fetch CSRF token (injects into response body)
            .route("/form", web::get().to(|csrf: CsrfToken| async move {
                HttpResponse::Ok().body(format!("token:{}", csrf.0))
            }))
            // Mutating endpoint (requires valid CSRF token in header or body)
            .route("/submit", web::post().to(|| async move { HttpResponse::Ok().finish() }))
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}

