use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken};
use actix_http::Request;
use actix_http::body::{BoxBody, EitherBody};
#[cfg(feature = "actix-session")]
use actix_session::{
    SessionMiddleware, config::CookieContentSecurity, storage::CookieSessionStore,
};
use actix_web::cookie::{Key, SameSite};
use actix_web::dev::{Service, ServiceResponse};
use actix_web::{App, HttpResponse, test, web};
use hmac::Hmac;
use sha2::Sha256;

pub type HmacSha256 = Hmac<Sha256>;

pub const HMAC_SECRET: &[u8] = b"secret-key";

pub fn test_key() -> Key {
    Key::generate()
}

pub async fn build_app(
    cfg: CsrfMiddlewareConfig,
) -> impl Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>
{
    test::init_service({
        let app = App::new().wrap(CsrfMiddleware::new(cfg));
        #[cfg(feature = "actix-session")]
        let app = app.wrap(get_session_middleware());
        app.configure(configure_routes)
    })
    .await
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/form",
        web::get().to(|csrf: CsrfToken| async move {
            HttpResponse::Ok().body(format!("token:{}", csrf.0))
        }),
    )
    .route(
        "/submit",
        web::post().to(|_csrf: CsrfToken| async move { HttpResponse::Ok().body("OK") }),
    )
    .route(
        "/submit_get",
        web::get().to(|| async move { HttpResponse::Ok().body("GET_OK") }),
    );
}

#[cfg(feature = "actix-session")]
fn get_session_middleware() -> SessionMiddleware<CookieSessionStore> {
    SessionMiddleware::builder(CookieSessionStore::default(), test_key())
        .cookie_content_security(CookieContentSecurity::Private)
        .cookie_secure(true)
        .cookie_http_only(true)
        .cookie_same_site(SameSite::Strict)
        .build()
}
