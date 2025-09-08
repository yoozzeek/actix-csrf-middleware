use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken};
use actix_web::{web, App, HttpResponse, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Example-only secret. Do not use in production.
    let secret = b"example-secret-key-please-change-32+bytes";
    let csrf_config = CsrfMiddlewareConfig::double_submit_cookie(secret);

    HttpServer::new(move || {
        App::new()
            .wrap(CsrfMiddleware::new(csrf_config.clone()))
            // Fetch CSRF token (injects into response body)
            .route("/form", web::get().to(|csrf: CsrfToken| async move {
                HttpResponse::Ok().body(format!("token:{}", csrf.0))
            }))
            // Mutating endpoint (requires valid CSRF token in header or body)
            .route("/submit", web::post().to(|| async move { HttpResponse::Ok().finish() }))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

