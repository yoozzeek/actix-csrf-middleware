use actix_csrf_middleware::{
    CsrfError, CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken, DEFAULT_CSRF_TOKEN_FIELD,
};
use actix_web::dev::ServiceResponse;
use actix_web::middleware::{ErrorHandlerResponse, ErrorHandlers};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};

// Recover the typed `CsrfError` from the
// response extensions and re-render it as HTML.
fn render_csrf_error<B>(res: ServiceResponse<B>) -> actix_web::Result<ErrorHandlerResponse<B>> {
    let code = res
        .response()
        .extensions()
        .get::<CsrfError>()
        .map(|err| err.code());

    let code = match code {
        Some(code) => code,
        None => return Ok(ErrorHandlerResponse::Response(res.map_into_left_body())),
    };

    let status = res.status();
    let (req, _) = res.into_parts();

    let rendered = HttpResponse::build(status)
        .content_type("text/html; charset=utf-8")
        .body(format!(
            "<!doctype html><h1>Request blocked</h1>\
             <p>CSRF check failed: <code>{code}</code></p>"
        ));

    Ok(ErrorHandlerResponse::Response(
        ServiceResponse::new(req, rendered).map_into_right_body(),
    ))
}

async fn render_form(csrf: CsrfToken) -> impl Responder {
    let html = format!(
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Double submit cookie example</title>
</head>
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
  <p>Send a forged token to see the rejection rendered by the ErrorHandlers:</p>
  <form method="post" action="/submit">
    <input type="hidden" name="{field}" value="forged-token-not-an-hmac" />
    <button type="submit">Submit invalid</button>
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
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Double submit cookie example</title></head>
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
    let secret = b"example-double-submit-secret-please-change-32+bytes";

    // secure=false: demo serves plain HTTP.
    let csrf_config = CsrfMiddlewareConfig::double_submit_cookie(secret).with_secure(false);

    println!("Starting actix web at http://localhost:8080...");

    HttpServer::new(move || {
        App::new()
            // ErrorHandlers is outermost so it sees the
            // rejection on its way out of CsrfMiddleware.
            .wrap(CsrfMiddleware::new(csrf_config.clone()))
            .wrap(ErrorHandlers::new().default_handler(render_csrf_error))
            // Display simple HTML form posting to /submit with csrf_token
            .route("/", web::get().to(render_form))
            // Mutating endpoint (requires valid CSRF token in header or body)
            .route("/submit", web::post().to(submit_handler))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
