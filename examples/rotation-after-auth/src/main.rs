use actix_csrf_middleware::{
    CsrfMiddleware, CsrfMiddlewareConfig, CsrfRequestExt, CsrfToken, DEFAULT_CSRF_TOKEN_FIELD,
    DEFAULT_CSRF_TOKEN_HEADER, DEFAULT_SESSION_ID_KEY,
};
use actix_web::{cookie::Cookie, web, App, HttpRequest, HttpResponse, HttpServer, Responder};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Example-only secret. Do not use in production.
    let secret = b"example-secret-key-please-change-32+bytes";
    let csrf_config = CsrfMiddlewareConfig::double_submit_cookie(secret);

    HttpServer::new(move || {
        App::new()
            .wrap(CsrfMiddleware::new(csrf_config.clone()))
            .route("/token", web::get().to(render_token))
            .route("/login", web::post().to(handle_login))
            // HTML form to /submit with csrf_token
            .route("/form", web::get().to(render_form))
            // Protected endpoint that rotates token upon success
            .route("/form", web::post().to(handle_form_rotate))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

async fn render_token(csrf: CsrfToken) -> impl Responder {
    HttpResponse::Ok().body(format!("token:{}", csrf.0))
}

// Simulate login by issuing a session id cookie, then redirect to /form
async fn handle_login() -> impl Responder {
    let session_cookie = Cookie::build(DEFAULT_SESSION_ID_KEY, "SID-LOGIN")
        .path("/")
        .finish();

    let mut resp = HttpResponse::SeeOther();
    resp.cookie(session_cookie);
    resp.append_header((actix_web::http::header::LOCATION, "/form"));
    resp.finish()
}

async fn render_form(csrf: CsrfToken) -> impl Responder {
    let html = format!(
        r#"<!doctype html>
<html>
<head><meta charset="utf-8"><title>CSRF Rotation Demo</title></head>
<body>
  <h1>Auth + Submit</h1>
  <!-- NOTE: normally csrf_token is a hidden input. Kept editable for testing. -->
  <section>
    <h2>1) Authorize</h2>
    <form method="post" action="/login">
      <label>csrf_token: <input type="text" name="{field}" value="{val}" /></label>
      <button type="submit">Login</button>
    </form>
  </section>

  <section>
    <h2>2) Protected submit (rotates token)</h2>
    <form method="post" action="/form">
      <label>csrf_token: <input type="text" name="{field}" value="{val}" /></label>
      <button type="submit">Submit</button>
    </form>
  </section>
</body>
</html>"#,
        field = DEFAULT_CSRF_TOKEN_FIELD,
        val = csrf.0
    );

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// Protected endpoint that also rotates CSRF token in response upon success
async fn handle_form_rotate(req: HttpRequest) -> actix_web::Result<HttpResponse> {
    let mut builder = HttpResponse::Ok();
    req.rotate_csrf_token_in_response(&mut builder)?;

    Ok(builder.body("CSRF token is valid (rotated)"))
}
