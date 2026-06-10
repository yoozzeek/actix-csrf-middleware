# actix-csrf-middleware

[![Crates.io](https://img.shields.io/crates/v/actix-csrf-middleware.svg)](https://crates.io/crates/actix-csrf-middleware)
[![Docs.rs](https://docs.rs/actix-csrf-middleware/badge.svg)](https://docs.rs/actix-csrf-middleware)
[![CI](https://github.com/yoozzeek/actix-csrf-middleware/actions/workflows/ci.yml/badge.svg)](https://github.com/yoozzeek/actix-csrf-middleware/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

CSRF protection middleware for [Actix Web](https://github.com/actix/actix-web) applications. Supports double submit
cookie and synchronizer token patterns (with actix-session) out of the box. Flexible, easy to configure, and includes
test coverage for common attacks and edge cases.

## ⚠️ Security Warning

This crate has not been audited and may contain bugs and security flaws.

USE AT YOUR OWN RISK!

## Overview

- Store CSRF tokens as:
    - Stateless double submit cookie
    - Synchronizer token in persistent storage via `actix-session`
- Implemented following
  the [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
    - CSRF token is a 256-bit cryptographically secure random value
    - For the double submit cookie pattern, hashes the session/pre-session ID with the CSRF token using HMAC-SHA256
    - Compares tokens in constant time to prevent timing attacks
- Protect unauthorized routes with signed, stateless pre-sessions (cookie is always HttpOnly=true, Secure=true,
  SameSite=Strict)
- Automatically extract and verify tokens from:
    - `application/json`
    - `application/x-www-form-urlencoded`
- Configurable cookie, header, and form field names
- Graceful, typed error handling: every rejection is a `CsrfError` rendered by default as
  `{"error":"<code>"}` (JSON, correct status) with stable machine-readable codes. The typed value is stored in
  the response extensions, so an actix `ErrorHandlers` can recover it and re-render in your own shape (HTML, JSON,
  problem+json). Internal faults are logged server-side and never leak details to the client.
- Optional Origin/Referer enforcement for mutating requests (configurable)
- Helpers for manually extracting and validating CSRF tokens at the handler level are useful for processing
  `multipart/form-data` requests without expensive body reading in middleware
- Enabled by default for all mutating (`POST`,`PUT`,`PATCH`,`DELETE`) http requests; supports per-path CSRF exclusion
  via `skip_for`.

## Quick start

Dependencies:

```toml
[dependencies]
actix-web = "4"
actix-csrf-middleware = "0.6"
```

Code:

```rust
use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};

async fn form(csrf: CsrfToken) -> impl Responder {
    HttpResponse::Ok().body(format!("csrf token: {}", csrf.0))
}

async fn submit() -> impl Responder {
    // Runs only after the CSRF token is verified.
    HttpResponse::Ok().body("accepted")
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    // >= 32 bytes; load from your config in production.
    let secret = b"replace-me-with-a-32+byte-application-secret";

    HttpServer::new(move || {
        // Constant secret, so tokens validate across workers.
        let config = CsrfMiddlewareConfig::double_submit_cookie(secret);
        App::new()
            .wrap(CsrfMiddleware::new(config))
            .route("/", web::get().to(form))
            .route("/submit", web::post().to(submit))
    })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
```

## Examples

Minimal runnable examples are provided in the examples directory:

- [Double Submit Cookie](examples/double-submit-cookie)
- [Synchronizer Token (requires `actix-session`)](examples/synchronizer-token)
- [Login/Logout Rotation (Double Submit Cookie + RequestExt
  rotate)](examples/login-logout-rotation)

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
