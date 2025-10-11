use actix_csrf_middleware::{
    CsrfMiddleware, CsrfMiddlewareConfig, CsrfRequestExt, CsrfToken, DEFAULT_CSRF_TOKEN_FIELD,
    DEFAULT_SESSION_ID_KEY,
};
use actix_web::cookie::{time, Cookie};
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};

// Simulate login by issuing a session id cookie, then redirect to /form
async fn login_handler(req: HttpRequest) -> actix_web::Result<HttpResponse> {
    let session_id = "auth-session-id";

    let mut resp = HttpResponse::SeeOther();
    let session_cookie = Cookie::build(DEFAULT_SESSION_ID_KEY, session_id)
        .path("/")
        .finish();

    // Set session cookie first
    resp.cookie(session_cookie);

    // Then rotate token
    req.rotate_csrf_token_in_response(session_id, &mut resp)?;

    resp.append_header((actix_web::http::header::LOCATION, "/page"));

    Ok(resp.finish())
}

async fn logout_handler() -> actix_web::Result<HttpResponse> {
    let mut resp = HttpResponse::SeeOther();

    // Delete session id cookie
    let mut del = Cookie::new(DEFAULT_SESSION_ID_KEY.to_string(), "");
    del.set_max_age(time::Duration::seconds(0));
    del.set_expires(time::OffsetDateTime::UNIX_EPOCH);
    del.set_path("/");
    resp.cookie(del);

    resp.append_header((actix_web::http::header::LOCATION, "/"));

    Ok(resp.finish())
}

async fn login_form(csrf: CsrfToken) -> impl Responder {
    let html = format!(
        r#"<!doctype html>
<html>
<head><meta charset="utf-8"><title>CSRF Rotation Demo</title></head>
<body>
  <h1>Rotate CSRF token after login</h1>
  <section style="max-width:460px;">
    <p>This example demonstrates how CSRF token classes work in practice on the example of login.</p>
    <p>
        Middleware generates pre-session and CSRF token of anonynous class to this operation.
        After sucessfull login (or registration) set session id as usually and call
        rotate_csrf_token_in_response to trigger CSRF token rotation. It will securly
        rotate previous anonynous token with authorized one that can be used on CSRF protected routes.
    </p>
    <p><code>{token}</code></p>
    <form style="display:flex;flex-direction:column;" method="post" action="/login">
      <input hidden type="text" name="{field}" value="{token}" />
      <button type="submit">Login</button>
    </form>
  </section>
</body>
</html>"#,
        field = DEFAULT_CSRF_TOKEN_FIELD,
        token = csrf.0
    );

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

async fn authorized_page(csrf: CsrfToken) -> impl Responder {
    let html = format!(
        r#"<!doctype html>
<html>
<head><meta charset="utf-8"><title>CSRF Rotation Demo</title></head>
<body>
  <h1>Authorized page</h1>
  <section style="max-width:460px;">
    <form style="display:flex;flex-direction:column;" method="post" action="/logout">
      <input hidden type="text" name="{field}" value="{token}" />
      <button type="submit">Logout</button>
    </form>
  </section>
</body>
</html>"#,
        field = DEFAULT_CSRF_TOKEN_FIELD,
        token = csrf.0
    );

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
            // HTML form to /submit with csrf_token
            .route("/", web::get().to(login_form))
            .route("/login", web::post().to(login_handler))
            .route("/logout", web::post().to(logout_handler))
            .route("/page", web::get().to(authorized_page))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
