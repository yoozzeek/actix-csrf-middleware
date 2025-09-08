use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig, CsrfRequestExt, CsrfToken, DEFAULT_CSRF_TOKEN_HEADER, DEFAULT_SESSION_ID_KEY};
use actix_web::{cookie::Cookie, web, App, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer, Responder};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Example-only secret. Do not use in production.
    let secret = b"example-secret-key-please-change-32+bytes";

    let csrf_config = CsrfMiddlewareConfig::double_submit_cookie(secret);

    HttpServer::new(move || {
        App::new()
            .wrap(CsrfMiddleware::new(csrf_config.clone()))
            .route("/form", web::get().to(form))
            .route("/login", web::post().to(login))
            .route("/auth", web::post().to(auth_rotate))
    })
    .bind(("127.0.0.1", 8082))?
    .run()
    .await
}

async fn form(csrf: CsrfToken) -> impl Responder {
    HttpResponse::Ok().body(format!("token:{}", csrf.0))
}

// Simulate login by issuing a session id cookie
async fn login() -> impl Responder {
    let session_cookie = Cookie::build(DEFAULT_SESSION_ID_KEY, "SID-LOGIN").path("/").finish();
    let mut resp = HttpResponse::NoContent();
    resp.cookie(session_cookie);
    resp.finish()
}

// Protected endpoint that also rotates CSRF token in response upon success
async fn auth_rotate(req: HttpRequest) -> actix_web::Result<HttpResponse> {
    // Quick header presence check; middleware will fully validate
    if req.headers().get(DEFAULT_CSRF_TOKEN_HEADER).is_none() {
        return Ok(HttpResponse::BadRequest().body("missing token header"));
    }

    // If we are here, middleware already validated CSRF
    let mut builder = HttpResponse::Ok();
    req.rotate_csrf_token_in_response(&mut builder)?;
    Ok(builder.finish())
}

