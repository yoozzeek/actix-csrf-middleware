# actix-csrf-middleware

CSRF protection middleware for [Actix Web](https://github.com/actix/actix-web) applications. Supports double submit
cookie and synchronizer token patterns (with actix-session) out of the box. Flexible, easy to
configure, and includes test coverage for common attacks and edge cases.

- Double submit cookie or actix session token storage
- Handles JSON and form submissions
- Configurable cookie, header name, form field, and error handler
- Per-path CSRF exclusion (skip_for)

## Example: Basic Usage

### Double Submit Cookie

With default configuration `CsrfMiddleware` uses double submit cookie pattern.

Dependencies:

```
[dependencies]
actix-csrf-middleware = "0.2"
```

Code:

```rust
use actix_web::{web, App, HttpServer, HttpResponse};
use actix_csrf_middleware::{CsrfMiddleware, CsrfToken};

fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(CsrfMiddleware::default())
            .route("/form", web::get().to(|csrf: CsrfToken| async move {
                // Inject CSRF token to your form
                HttpResponse::Ok().body(format!("token:{}", csrf.0))
            }))
            .route("/submit", web::post().to(|| async move {
                // Only called if CSRF is valid
                HttpResponse::Ok().body("OK")
            }))
    })
        .bind(("127.0.0.1", 8080))?
        .run()
}
```

### Synchronizer Token (actix-session)

To enable the synchronizer token pattern activate session feature and wrap with session middleware (
see [actix-session](https://docs.rs/actix-session)):

Dependencies:

```
[dependencies]
actix-csrf-middleware = { version = "0.2", features = ["session"] }
```

Code:

```rust
use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig, CsrfPattern, CsrfToken};
use actix_session::{SessionMiddleware, storage::CookieSessionStore};

fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(CsrfMiddleware::default())
            // or
            // .wrap(CsrfMiddleware::new(CsrfMiddlewareConfig {
            //     pattern: CsrfPattern::SynchronizerToken,
            //     ..CsrfMiddlewareConfig::default()
            // }))
            .wrap(SessionMiddleware::new(CookieSessionStore::default(), your_secret_key()))
        // Your routes...
    })
        .bind(("127.0.0.1", 8080))?
        .run()
}
```

## Configuration

```rust
use actix_csrf_middleware::{CsrfDoubleSubmitCookieConfig};

fn build_custom_csrf_config() {
    CsrfDoubleSubmitCookieConfig {
        pattern: CsrfPattern::SynchronizerToken, // or CsrfPattern::DoubleSubmitCookie
        cookie_name: "csrf-token".to_string(),
        form_field: "csrf_token".to_string(),
        header_name: "X-CSRF-Token".to_string(),
        secure: true, // strictly required in prod
        same_site: SameSite::Strict,
        skip_for: vec!["/api/".to_string()], // Skip CSRF checks for certain paths
        on_error: Rc::new(|_| HttpResponse::Forbidden().body("Invalid CSRF token")),
    }
}
```

## Security

> This code is implemented
>
following [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
> It uses simple and robust double submit cookie pattern.

- Token is 256-bit, base64url encoded, cryptographically secure random
- Compares tokens in constant time to prevent timing attacks
- Secure cookie options (SameSite, Secure, HttpOnly) enabled by default
- All mutating requests (POST/PUT/PATCH/DELETE) are protected

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
