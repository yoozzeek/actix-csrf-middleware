use actix_csrf_middleware::{
    CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken, DEFAULT_COOKIE_NAME, DEFAULT_FORM_FIELD,
    DEFAULT_HEADER, PRE_SESSION_COOKIE_NAME,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct TrackingAllocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static DEALLOCATED: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc(layout);
        if !ret.is_null() {
            ALLOCATED.fetch_add(layout.size(), Ordering::SeqCst);
        }
        ret
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        DEALLOCATED.fetch_add(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

fn get_memory_usage() -> (usize, usize) {
    let allocated = ALLOCATED.load(Ordering::SeqCst);
    let deallocated = DEALLOCATED.load(Ordering::SeqCst);
    (allocated, allocated.saturating_sub(deallocated))
}
#[cfg(feature = "actix-session")]
use actix_session::{
    SessionMiddleware, config::CookieContentSecurity, storage::CookieSessionStore,
};
use actix_web::cookie::Key;
use actix_web::http::header::ContentType;
use actix_web::{App, HttpResponse, test, web};
use serde_json::json;
use std::time::Instant;

fn secret_key() -> Vec<u8> {
    b"super_secret_Key".to_vec()
}

fn test_key() -> Key {
    Key::generate()
}

fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/form",
        web::get().to(|csrf: CsrfToken| async move {
            HttpResponse::Ok().body(format!("token:{}", csrf.0))
        }),
    )
    .route(
        "/submit",
        web::post().to(|_csrf: CsrfToken| async move { HttpResponse::Ok().body("OK") }),
    );
}

#[cfg(feature = "actix-session")]
fn get_session_middleware() -> SessionMiddleware<CookieSessionStore> {
    SessionMiddleware::builder(CookieSessionStore::default(), test_key())
        .cookie_content_security(CookieContentSecurity::Private)
        .cookie_secure(true)
        .cookie_http_only(true)
        .cookie_same_site(actix_web::cookie::SameSite::Strict)
        .build()
}

#[cfg(feature = "actix-session")]
async fn synchronizer_token_benchmark() {
    println!("\nSynchronizer Token Pattern:");
    println!("---------------------------");

    let (_start_allocated, start_net) = get_memory_usage();
    let _start_time = Instant::now();

    let cfg = CsrfMiddlewareConfig::synchronizer_token();
    let app = test::init_service(
        App::new()
            .wrap(CsrfMiddleware::new(cfg))
            .wrap(get_session_middleware())
            .configure(configure_routes),
    )
    .await;

    let iterations = 100000;
    let start = Instant::now();

    for _ in 0..iterations {
        // 1. GET /form
        let req = test::TestRequest::get().uri("/form").to_request();
        let resp = test::call_service(&app, req).await;

        let token_cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == "id")
            .map(|c| c.into_owned())
            .unwrap();
        let body = test::read_body(resp).await;
        let token = String::from_utf8(body.to_vec()).unwrap();
        let token = token.strip_prefix("token:").unwrap();

        // 2. POST /submit
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_HEADER, token))
            .cookie(token_cookie)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    let (_end_allocated, end_net) = get_memory_usage();
    let elapsed = start.elapsed();
    println!("\nParse token from header:");
    println!(
        "After {} iterations - Allocated: {} bytes, Net: {} bytes",
        iterations,
        end_net - start_net,
        end_net - start_net
    );
    println!("Time elapsed: {:?}", elapsed);
    println!(
        "Requests per second: {:.2}",
        iterations as f64 / elapsed.as_secs_f64()
    );

    let start = Instant::now();

    for _ in 0..iterations {
        let req = test::TestRequest::get().uri("/form").to_request();
        let resp = test::call_service(&app, req).await;

        let token_cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == "id")
            .map(|c| c.into_owned())
            .unwrap();
        let body = test::read_body(resp).await;
        let token = String::from_utf8(body.to_vec()).unwrap();
        let token = token.strip_prefix("token:").unwrap();

        let form = format!(
            "{}={}&large_field={}",
            DEFAULT_FORM_FIELD,
            token,
            "a".repeat(1024)
        );
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header(ContentType::form_url_encoded())
            .cookie(token_cookie)
            .set_payload(form)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    let (_end_allocated, end_net) = get_memory_usage();
    let elapsed = start.elapsed();
    println!("\nParse token from form field:");
    println!(
        "After {} iterations - Allocated: {} bytes, Net: {} bytes",
        iterations,
        end_net - start_net,
        end_net - start_net
    );
    println!("Time elapsed: {:?}", elapsed);
    println!(
        "Requests per second: {:.2}",
        iterations as f64 / elapsed.as_secs_f64()
    );

    let start = Instant::now();

    for _ in 0..iterations {
        let req = test::TestRequest::get().uri("/form").to_request();
        let resp = test::call_service(&app, req).await;

        let token_cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == "id")
            .map(|c| c.into_owned())
            .unwrap();
        let body = test::read_body(resp).await;
        let token = String::from_utf8(body.to_vec()).unwrap();
        let token = token.strip_prefix("token:").unwrap();

        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header(ContentType::form_url_encoded())
            .cookie(token_cookie)
            .set_json(json!({
                DEFAULT_FORM_FIELD: token
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    let (_end_allocated, end_net) = get_memory_usage();
    let elapsed = start.elapsed();
    println!("\nParse token from json payload:");
    println!(
        "After {} iterations - Allocated: {} bytes, Net: {} bytes",
        iterations,
        end_net - start_net,
        end_net - start_net
    );
    println!("Time elapsed: {:?}", elapsed);
    println!(
        "Requests per second: {:.2}",
        iterations as f64 / elapsed.as_secs_f64()
    );
}

async fn double_submit_cookie_benchmark() {
    println!("\nSigned Double Submit Cookie Pattern:");
    println!("----------------------------");

    let (_start_allocated, start_net) = get_memory_usage();
    let _start_time = Instant::now();

    let cfg = CsrfMiddlewareConfig::double_submit_cookie(&secret_key());
    let app = test::init_service(
        App::new()
            .wrap(CsrfMiddleware::new(cfg))
            .configure(configure_routes),
    )
    .await;

    let iterations = 100000;
    let start = Instant::now();

    for _ in 0..iterations {
        let req = test::TestRequest::get().uri("/form").to_request();
        let resp = test::call_service(&app, req).await;

        let session_id_cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == PRE_SESSION_COOKIE_NAME)
            .map(|c| c.into_owned())
            .unwrap();

        let token_cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == DEFAULT_COOKIE_NAME)
            .map(|c| c.into_owned())
            .unwrap();
        let body = test::read_body(resp).await;
        let token = String::from_utf8(body.to_vec()).unwrap();
        let token = token.strip_prefix("token:").unwrap();

        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header((DEFAULT_HEADER, token))
            .cookie(token_cookie)
            .cookie(session_id_cookie)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    let (_end_allocated, end_net) = get_memory_usage();
    let elapsed = start.elapsed();
    println!("\nParse token from header:");
    println!(
        "After {} iterations - Allocated: {} bytes, Net: {} bytes",
        iterations,
        end_net - start_net,
        end_net - start_net
    );
    println!("Time elapsed: {:?}", elapsed);
    println!(
        "Requests per second: {:.2}",
        iterations as f64 / elapsed.as_secs_f64()
    );

    let start = Instant::now();

    for _ in 0..iterations {
        let req = test::TestRequest::get().uri("/form").to_request();
        let resp = test::call_service(&app, req).await;

        let session_id_cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == PRE_SESSION_COOKIE_NAME)
            .map(|c| c.into_owned())
            .unwrap();

        let token_cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == DEFAULT_COOKIE_NAME)
            .map(|c| c.into_owned())
            .unwrap();
        let body = test::read_body(resp).await;
        let token = String::from_utf8(body.to_vec()).unwrap();
        let token = token.strip_prefix("token:").unwrap();

        let form = format!(
            "{}={}&large_field={}",
            DEFAULT_FORM_FIELD,
            token,
            "a".repeat(1024)
        );
        let req = test::TestRequest::post()
            .uri("/submit")
            .insert_header(ContentType::form_url_encoded())
            .cookie(token_cookie)
            .cookie(session_id_cookie)
            .set_payload(form)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    let (end_allocated, end_net) = get_memory_usage();
    let elapsed = start.elapsed();
    println!("\nParse token from form field:");
    println!(
        "After {} iterations - Allocated: {} bytes, Net: {} bytes",
        iterations,
        end_net - start_net,
        end_net - start_net
    );
    println!("Time elapsed: {:?}", elapsed);
    println!(
        "Requests per second: {:.2}",
        iterations as f64 / elapsed.as_secs_f64()
    );

    let start = Instant::now();

    for _ in 0..iterations {
        let req = test::TestRequest::get().uri("/form").to_request();
        let resp = test::call_service(&app, req).await;

        let session_id_cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == PRE_SESSION_COOKIE_NAME)
            .map(|c| c.into_owned())
            .unwrap();

        let token_cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == DEFAULT_COOKIE_NAME)
            .map(|c| c.into_owned())
            .unwrap();
        let body = test::read_body(resp).await;
        let token = String::from_utf8(body.to_vec()).unwrap();
        let token = token.strip_prefix("token:").unwrap();

        let req = test::TestRequest::post()
            .uri("/submit")
            .cookie(token_cookie)
            .cookie(session_id_cookie)
            .set_json(json!({
                DEFAULT_FORM_FIELD: token
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    let (_end_allocated, end_net) = get_memory_usage();
    let elapsed = start.elapsed();
    println!("\nParse token from json payload:");
    println!(
        "After {} iterations - Allocated: {} bytes, Net: {} bytes",
        iterations,
        end_net - start_net,
        end_net - start_net
    );
    println!("Time elapsed: {:?}", elapsed);
    println!(
        "Requests per second: {:.2}",
        iterations as f64 / elapsed.as_secs_f64()
    );
}

#[actix_rt::main]
async fn main() {
    println!("HTTP Performance Benchmarks for actix-csrf-middleware");
    println!("======================================================");

    // Reset memory counters
    ALLOCATED.store(0, Ordering::SeqCst);
    DEALLOCATED.store(0, Ordering::SeqCst);

    #[cfg(feature = "actix-session")]
    {
        synchronizer_token_benchmark().await;
    }
    double_submit_cookie_benchmark().await;
}
