use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken, DEFAULT_COOKIE_NAME};
use actix_http::Request;
use actix_http::body::{BoxBody, EitherBody};
#[cfg(feature = "actix-session")]
use actix_session::{
    SessionMiddleware, config::CookieContentSecurity, storage::CookieSessionStore,
};
use actix_web::cookie::{Cookie, Key, SameSite};
use actix_web::dev::{Service, ServiceResponse};
use actix_web::{App, HttpResponse, test, web};

pub fn test_key() -> Key {
    Key::generate()
}

pub async fn build_app(
    cfg: Option<CsrfMiddlewareConfig>,
) -> impl Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>
{
    let cfg = cfg.unwrap_or_default();
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

pub async fn token_cookie<S>(app: &S, custom_name: Option<&str>) -> (String, Cookie<'static>)
where
    S: Service<Request, Response = ServiceResponse<EitherBody<BoxBody>>, Error = actix_web::Error>,
{
    let req = test::TestRequest::get().uri("/form").to_request();
    let resp = test::call_service(&app, req).await;

    let cookie_name = if let Some(name) = custom_name {
        name
    } else {
        DEFAULT_COOKIE_NAME
    };

    let cookie = resp
        .response()
        .cookies()
        .find(|c| c.name() == cookie_name)
        .map(|c| c.into_owned())
        .unwrap();

    let body = test::read_body(resp).await;
    let token = String::from_utf8(body.to_vec()).unwrap();
    let token = token.strip_prefix("token:").unwrap().to_string();

    (token, cookie)
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
