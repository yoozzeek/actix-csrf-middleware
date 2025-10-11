use actix_csrf_middleware::{
    CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken, DEFAULT_CSRF_TOKEN_FIELD,
};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};

async fn render_form(csrf: CsrfToken) -> impl Responder {
    let html = format!(
        r#"<!doctype html>
<html>
<head><meta charset="utf-8"><title>Double submit cookie example</title></head>
<body>
  <h1>Double Submit Cookie</h1>
  <p>For the double submit cookie pattern, middleware hashes the session/pre-session ID with the CSRF token using HMAC-SHA256.</p>
  <p>Automatically extract and verify tokens from:
    <code>application/json</code>,
    <code>application/x-www-form-urlencoded</code>.
  </p>
  <form method="post" action="/submit">
    <input type="hidden" name="{field}" value="{val}" />
    <div><textarea disabled style="width:360px;" rows="3" name="{field}">{val}</textarea></div>
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

async fn submit_handler() -> impl Responder {
    let html = r#"<!doctype html>
<html>
<head><meta charset="utf-8"><title>Double submit cookie example</title></head>
<body>
  <h1>Double Submit Cookie</h1>
  <p>CSRF token is valid</p>
  <form method="get" action="/">
    <button>Start again</button>
  </form>
</body>
</html>"#
        .to_string();

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Example-only secret. Do not use in production.
    let secret = b"example-secret-key-please-change-32+bytes";
    let csrf_config = CsrfMiddlewareConfig::double_submit_cookie(secret);

    println!("Starting actix web at http://localhost:8080...");

    HttpServer::new(move || {
        App::new()
            .wrap(CsrfMiddleware::new(csrf_config.clone()))
            // Display simple HTML form posting to /submit with csrf_token
            .route("/", web::get().to(render_form))
            // Mutating endpoint (requires valid CSRF token in header or body)
            .route("/submit", web::post().to(submit_handler))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
