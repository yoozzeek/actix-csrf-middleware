# actix-csrf-middleware

[![CI](https://github.com/yoozzeek/actix-csrf-middleware/actions/workflows/ci.yml/badge.svg)](https://github.com/yoozzeek/actix-csrf-middleware/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/actix-csrf-middleware.svg)](https://crates.io/crates/actix-csrf-middleware)
[![Docs.rs](https://docs.rs/actix-csrf-middleware/badge.svg)](https://docs.rs/actix-csrf-middleware)
[![Downloads](https://img.shields.io/crates/d/actix-csrf-middleware.svg)](https://crates.io/crates/actix-csrf-middleware)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

CSRF protection middleware for [Actix Web](https://github.com/actix/actix-web) applications. Supports double submit
cookie and synchronizer token patterns (with actix-session) out of the box. Flexible, easy to configure, and includes
test coverage for common attacks and edge cases.

**WARNING:** This crate has not been audited and may contain bugs and security flaws. This implementation is NOT ready
for production use.

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
- Optional Origin/Referer enforcement for mutating requests (configurable)
- Helpers for manually extracting and validating CSRF tokens at the handler level are useful for processing
  `multipart/form-data` requests without expensive body reading in middleware
- Enabled by default for all mutating (`POST`,`PUT`,`PATCH`,`DELETE`) http requests; supports per-path CSRF exclusion
  via `skip_for`.

## Examples

Minimal runnable examples are provided in the examples directory:

- Double Submit Cookie: [examples/double-submit-cookie](examples/double-submit-cookie)
- Synchronizer Token (requires `actix-session`): [examples/synchronizer-token](examples/synchronizer-token)
- Rotation After Auth (Double Submit Cookie + RequestExt rotate): [examples/rotation-after-auth](examples/rotation-after-auth)

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
