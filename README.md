# actix-csrf-middleware

CSRF protection middleware for [Actix Web](https://github.com/actix/actix-web) applications. Supports double submit
cookie and synchronizer token patterns (with actix-session) out of the box. Flexible, easy to
configure, and includes test coverage for common attacks and edge cases.

- Double submit cookie or actix session token storage
- Handles JSON and form submissions
- Configurable cookie, header name, form field, and error handler
- Per-path CSRF exclusion (skip_for)

## Examples

### Basic Usage: Signed Double Submit Cookie

By default, CsrfMiddleware uses the signed double submit cookie pattern (per OWASP). CSRF validation relies solely on
the cookie and request header/body, not a backend session store. `HttpOnly=false` is set for the CSRF cookie so that
modern frontend frameworks can read and transmit the token in a custom header.

The token is generated as:<br>

```
hmac = HMAC_SHA256(secret_key, session_or_pre_session_id + "!" + csrf_token) 
token = hmac + "." + csrf_token
```

Dependencies:

```
[dependencies]
actix-csrf-middleware = { git = "https://github.com/yoozzeek/actix-csrf-middleware.git" }
```

Code:

```rust
use actix_web::{web, App, HttpServer, HttpResponse};
use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken};

fn main() -> std::io::Result<()> {
    let csrf_config = CsrfMiddlewareConfig::double_submit_cookie();
    HttpServer::new(|| {
        App::new()
            .wrap(CsrfMiddleware::new(csrf_config))
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

### Synchronizer Token

To enable the synchronizer token pattern activate session feature and wrap with `actix-session` middleware
(see [actix-session](https://docs.rs/actix-session)).

Dependencies:

```
[dependencies]
actix-csrf-middleware = { git = "https://github.com/yoozzeek/actix-csrf-middleware.git", features = ["session"] }
```

Code:

```rust
use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig, CsrfPattern, CsrfToken};
use actix_session::{SessionMiddleware, storage::CookieSessionStore};

fn main() -> std::io::Result<()> {
    let session_store = CookieSessionStore::default(); // you can use redis here
    let csrf_config = CsrfMiddlewareConfig::synchronizer_token();

    HttpServer::new(|| {
        App::new()
            .wrap(CsrfMiddleware::new(csrf_config))
            .wrap(SessionMiddleware::new(session_store, your_secret_key()))
    })
        .bind(("127.0.0.1", 8080))?
        .run()
}
```

### Custom Configuration

```rust
use actix_csrf_middleware::{CsrfMiddlewareConfig};

fn build_custom_config() {
    CsrfMiddlewareConfig {
        pattern: CsrfPattern::SynchronizerToken,
        session_id_cookie_name: "session-id".to_string(),
        token_cookie_name: "csrf-token".to_string(),
        token_form_field: "csrf_token".to_string(),
        token_header_name: "X-CSRF-Token".to_string(),
        token_cookie_config: Some(CsrfDoubleSubmitCookie {
            http_only: true,
            secure: true,
            same_site: SameSite::Lax,
        }),
        secret_key: Some(b"seper-secret-key".to_vec()),
        skip_for: vec!["/api/".to_string()], // Skip CSRF checks for certain paths
        on_error: Rc::new(|_| HttpResponse::Forbidden().body("Invalid CSRF token")),
    }
}
```

## Security

This code is implemented
following [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
It uses simple and robust double submit cookie pattern.

- Uses the signed double submit cookie pattern (per OWASP)
- Token is 256-bit, base64url encoded, cryptographically secure random
- Secure against CSRF and cookie injection (using HMAC with session/pre-session ID)
- All mutating requests (POST/PUT/PATCH/DELETE) are protected by default
- Compares tokens in constant time to prevent timing attacks

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
