use actix_csrf_middleware::{
    CsrfDoubleSubmitCookie, CsrfMiddleware, CsrfMiddlewareConfig, DEFAULT_CSRF_TOKEN_HEADER,
    DEFAULT_SESSION_ID_KEY, TokenClass, generate_hmac_token_ctx,
};
use actix_http::Request;
use actix_http::body::{BoxBody, EitherBody};
use actix_web::cookie::SameSite;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::header;
use actix_web::{App, HttpResponse, test, web};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);

        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(
            new_size.saturating_sub(layout.size()) as u64,
            Ordering::Relaxed,
        );

        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

type Scenario = (&'static str, Box<dyn Fn() -> Request>);

const SECRET: &[u8] = b"bench-secret-bench-secret-bench-1234567890";
const SID: &str = "BENCH-SESSION-ID";
const SKIP_PREFIX: &str = "/healthz";
const ITERS: usize = 200;

trait BenchService<B>:
    Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>
{
}

impl<S, B> BenchService<B> for S where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>
{
}

fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/form",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    )
    .route(
        "/submit",
        web::post().to(|| async { HttpResponse::Ok().finish() }),
    )
    .route(
        SKIP_PREFIX,
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    );
}

fn double_submit_config() -> CsrfMiddlewareConfig {
    CsrfMiddlewareConfig::double_submit_cookie(SECRET)
        .with_token_cookie_config(CsrfDoubleSubmitCookie {
            http_only: false,
            same_site: SameSite::Lax,
        })
        .with_secure(false)
        .with_skip_for(vec![SKIP_PREFIX.to_owned()])
}

async fn plain_app() -> impl BenchService<BoxBody> {
    test::init_service(App::new().configure(routes)).await
}

async fn double_submit_app() -> impl BenchService<EitherBody<BoxBody>> {
    test::init_service(
        App::new()
            .wrap(CsrfMiddleware::new(double_submit_config()))
            .configure(routes),
    )
    .await
}

fn authorized_token() -> String {
    generate_hmac_token_ctx(TokenClass::Authorized, SID, SECRET)
}

fn get_cold() -> Request {
    test::TestRequest::get().uri("/form").to_request()
}

fn get_warm(token: &str) -> Request {
    test::TestRequest::get()
        .uri("/form")
        .insert_header((
            header::COOKIE,
            format!("{DEFAULT_SESSION_ID_KEY}={SID}; CSRF={token}"),
        ))
        .to_request()
}

fn post_header(token: &str) -> Request {
    test::TestRequest::post()
        .uri("/submit")
        .insert_header((header::COOKIE, format!("{DEFAULT_SESSION_ID_KEY}={SID}")))
        .insert_header((DEFAULT_CSRF_TOKEN_HEADER, token.to_owned()))
        .to_request()
}

fn post_json(token: &str, padding: usize, declare_length: bool) -> Request {
    let body = format!(
        r#"{{"csrf_token":"{token}","payload":"{}"}}"#,
        "x".repeat(padding)
    );

    let req = test::TestRequest::post()
        .uri("/submit")
        .insert_header((header::COOKIE, format!("{DEFAULT_SESSION_ID_KEY}={SID}")))
        .insert_header((header::CONTENT_TYPE, "application/json"));

    let req = match declare_length {
        true => req.insert_header((header::CONTENT_LENGTH, body.len().to_string())),
        false => req,
    };

    req.set_payload(body).to_request()
}

fn post_json_whitespace(token: &str, padding: usize) -> Request {
    let body = format!(r#"{{"csrf_token":"{token}"{}}}"#, " ".repeat(padding));

    test::TestRequest::post()
        .uri("/submit")
        .insert_header((header::COOKIE, format!("{DEFAULT_SESSION_ID_KEY}={SID}")))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header((header::CONTENT_LENGTH, body.len().to_string()))
        .set_payload(body)
        .to_request()
}

fn post_form(token: &str, padding: usize) -> Request {
    let body = format!("csrf_token={token}&payload={}", "x".repeat(padding));

    test::TestRequest::post()
        .uri("/submit")
        .insert_header((header::COOKIE, format!("{DEFAULT_SESSION_ID_KEY}={SID}")))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header((header::CONTENT_LENGTH, body.len().to_string()))
        .set_payload(body)
        .to_request()
}

fn skipped() -> Request {
    test::TestRequest::get().uri(SKIP_PREFIX).to_request()
}

fn measure<S: BenchService<B>, B>(
    rt: &actix_rt::Runtime,
    srv: &S,
    make: &dyn Fn() -> Request,
) -> (f64, f64) {
    for _ in 0..16 {
        let _ = rt.block_on(srv.call(make())).expect("warmup call");
    }

    let requests: Vec<Request> = (0..ITERS).map(|_| make()).collect();

    ALLOCS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);

    for req in requests {
        let _ = rt.block_on(srv.call(req)).expect("measured call");
    }

    let allocs = ALLOCS.load(Ordering::Relaxed) as f64 / ITERS as f64;
    let bytes = BYTES.load(Ordering::Relaxed) as f64 / ITERS as f64;

    (allocs, bytes)
}

fn main() {
    let rt = actix_rt::Runtime::new().expect("bench runtime");
    let plain = rt.block_on(plain_app());
    let guarded = rt.block_on(double_submit_app());

    let token = authorized_token();

    let scenarios: Vec<Scenario> = vec![
        ("get_issue_tokens", Box::new(get_cold)),
        ("get_existing_tokens", {
            let t = token.clone();
            Box::new(move || get_warm(&t))
        }),
        ("skipped_prefix", Box::new(skipped)),
        ("post_token_in_header", {
            let t = token.clone();
            Box::new(move || post_header(&t))
        }),
        ("post_json_1k", {
            let t = token.clone();
            Box::new(move || post_json(&t, 1024, true))
        }),
        ("post_json_256k", {
            let t = token.clone();
            Box::new(move || post_json(&t, 256 * 1024, true))
        }),
        ("post_json_256k_whitespace", {
            let t = token.clone();
            Box::new(move || post_json_whitespace(&t, 256 * 1024))
        }),
        ("post_form_256k", {
            let t = token.clone();
            Box::new(move || post_form(&t, 256 * 1024))
        }),
    ];

    println!(
        "{:<26} {:>10} {:>12} {:>10} {:>12} {:>10} {:>12}",
        "scenario", "base/req", "base B/req", "csrf/req", "csrf B/req", "d allocs", "d bytes"
    );

    for (name, make) in &scenarios {
        let (base_allocs, base_bytes) = measure(&rt, &plain, make.as_ref());
        let (csrf_allocs, csrf_bytes) = measure(&rt, &guarded, make.as_ref());

        println!(
            "{:<26} {:>10.1} {:>12.0} {:>10.1} {:>12.0} {:>10.1} {:>12.0}",
            name,
            base_allocs,
            base_bytes,
            csrf_allocs,
            csrf_bytes,
            csrf_allocs - base_allocs,
            csrf_bytes - base_bytes
        );
    }
}
