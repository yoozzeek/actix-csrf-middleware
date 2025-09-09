use actix_csrf_middleware::{
    CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken, DEFAULT_CSRF_TOKEN_FIELD,
    DEFAULT_SESSION_ID_KEY,
};
use actix_session::{
    config::CookieContentSecurity, storage::CookieSessionStore, SessionMiddleware,
};
use actix_web::{
    cookie::{Key, SameSite},
    web, App, HttpResponse, HttpServer, Responder,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Example-only secret. Do not use in production.
    let secret = b"example-secret-key-please-change-32+bytes";
    let csrf_config = CsrfMiddlewareConfig::synchronizer_token(secret);
    let session_key = Key::generate();

    HttpServer::new(move || {
        App::new()
            .wrap(CsrfMiddleware::new(csrf_config.clone()))
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                    .cookie_content_security(CookieContentSecurity::Private)
                    .cookie_name(DEFAULT_SESSION_ID_KEY.to_string())
                    .cookie_secure(false) // for local demo only
                    .cookie_http_only(true)
                    .cookie_same_site(SameSite::Lax)
                    .build(),
            )
            // Fetch CSRF token (injects into response body)
            .route(
                "/token",
                web::get().to(|csrf: CsrfToken| async move {
                    HttpResponse::Ok().body(format!("token:{}", csrf.0))
                }),
            )
            // Display simple HTML form posting to /form with csrf_token
            .route("/form", web::get().to(render_form))
            // Mutating endpoint (requires valid CSRF token in body)
            .route(
                "/form",
                web::post().to(|| async move { HttpResponse::Ok().body("CSRF token is valid") }),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

async fn render_form(csrf: CsrfToken) -> impl Responder {
    let html = format!(
        r#"<!doctype html>
<html>
<head><meta charset="utf-8"><title>CSRF Demo</title></head>
<body>
  <h1>Submit form</h1>
  <!-- NOTE: normally csrf_token is a hidden input. Kept editable for testing. -->
  <form method="post" action="/form">
    <label>csrf_token: <input type="text" name="{field}" value="{val}" /></label>
    <button type="submit">Submit</button>
  </form>
</body>
</html>"#,
        field = DEFAULT_CSRF_TOKEN_FIELD,
        val = csrf.0
    );

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}
