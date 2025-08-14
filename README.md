# actix-csrf-middleware

CSRF protection middleware for [Actix Web](https://github.com/actix/actix-web) applications. Supports double submit
cookie and synchronizer token patterns (with actix-session) out of the box. Flexible, easy to configure, and includes
test coverage for common attacks and edge cases.

- Store CSRF tokens as:
    - Stateless double submit cookie
    - Synchronizer token in persistent storage via `actix-session`
- Implemented following
  the [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
    - CSRF token is a 256-bit cryptographically secure random value
    - For the double submit cookie pattern, hashes the session/pre-session ID with the CSRF token using HMAC-SHA256
- Protect unauthorized routes with signed, stateless pre-sessions
- Automatically extract and verify tokens from:
    - `application/json`
    - `application/x-www-form-urlencoded`
- Configurable cookie, header, and form field names
- Helpers for manually extracting and validating CSRF tokens at the handler level—useful for protecting
  `multipart/form-data` requests with binary files without reading the body in middleware
- Enabled by default for all requests; supports per-path CSRF exclusion via `skip_for`
- Custom error handler (coming soon)

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
            // Wraps all routes and enabled protection
            .wrap(CsrfMiddleware::new(csrf_config))
            // Inject CSRF token to your form
            .route("/form", web::get().to(|csrf: CsrfToken| async move {
                HttpResponse::Ok().body(format!("token:{}", csrf.0))
            }))
            // Only called if CSRF token is valid
            .route("/submit", web::post().to(|| async move {
                HttpResponse::Ok().body("OK")
            }))
    })
        .bind(("127.0.0.1", 8080))?
        .run()
}
```

### Synchronizer Token

To enable the synchronizer token pattern activate session feature and wrap with `actix-session` middleware (
see [actix-session](https://docs.rs/actix-session)).

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

You can create custom configuration defining `CsrfMiddlewareConfig` struct. In case of using
default configuration builders `CsrfMiddlewareConfig::synchronizer_token` or
`CsrfMiddlewareConfig::double_submit_cookie` you can configure middleware with
special methods such as `with_skip_for`, `with_multipart`, `with_on_error`, etc.

#### CsrfMiddlewareConfig

* `pattern`: configure which pattern to use to store CSRF tokens
* `session_id_cookie_name`:
* `token_cookie_name`:
* `token_form_field`:
* `token_header_name`:
* `token_cookie_config`:
* `secret_key`:
* `skip_for`:
* `on_error`:

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
