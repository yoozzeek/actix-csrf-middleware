# actix-csrf-middleware

CSRF protection middleware for [Actix Web](https://github.com/actix/actix-web) applications. Supports both double submit
cookie and synchronizer token patterns. Flexible, easy to
configure, and includes test coverage for common attacks and edge cases.

- Double submit cookie or actix session token storage
- Handles JSON and form submissions from the box
- Utils for implementing Synchronizer Token Pattern
- Configurable cookie name, header name, form field, and error handler
- Per-path CSRF exclusion (skip_for)

## Example: Basic Usage

### Simple middleware

```rust
use actix_web::{web, App, HttpServer, HttpResponse};
use actix_csrf_middleware::{
    CsrfDoubleSubmitCookieMiddleware, CsrfDoubleSubmitCookieConfig, CsrfStorage, CsrfToken,
};

fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(CsrfDoubleSubmitCookieMiddleware::default())
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

### With actix-session

Enable the session feature and wrap with session middleware (see [actix-session](https://docs.rs/actix-session)):

```rust
use actix_session::{SessionMiddleware, storage::CookieSessionStore};

fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(SessionMiddleware::new(CookieSessionStore::default(), your_secret_key()))
            .wrap(CsrfDoubleSubmitCookieMiddleware::new(CsrfDoubleSubmitCookieConfig {
                storage: CsrfStorage::Session,
                ..Default::default()
            }))
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
        storage: CsrfStorage::Session, // or CsrfStorage::Cookie
        cookie_name: "csrf-token".to_string(),
        form_field: "csrf_token".to_string(),
        header_name: "X-CSRF-Token".to_string(),
        secure: true, // Set Secure flag (should be true for production)
        same_site: SameSite::Strict,
        skip_for: vec!["/api/".to_string()], // Skip CSRF checks for certain paths
        on_error: Rc::new(|_| HttpResponse::Forbidden().body("Invalid CSRF token")),
    }
}
```

## Security

- Token is 256-bit, base64url encoded, cryptographically secure random
- Compares tokens in constant time to prevent timing attacks
- Secure cookie options (SameSite, Secure, HttpOnly) enabled by default
- All mutating requests (POST/PUT/PATCH/DELETE) are protected

> **Security:**  
> This middleware was implemented following the best practices from
> the [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
> It uses simple and robust double submit cookie pattern.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
