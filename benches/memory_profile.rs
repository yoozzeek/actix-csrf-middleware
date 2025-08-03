use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken};
#[cfg(feature = "session")]
use actix_session::{SessionMiddleware, config::CookieContentSecurity, storage::CookieSessionStore};
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, test, web};
#[cfg(feature = "session")]
use actix_web::cookie::Key;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

// Custom allocator to track memory usage
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

async fn handler(_req: HttpRequest, token: CsrfToken) -> HttpResponse {
    HttpResponse::Ok().body(format!("CSRF Token: {}", token.0))
}

async fn post_handler(_req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().body("POST request processed")
}

#[actix_rt::main]
async fn main() {
    println!("Memory and CPU profiling for actix-csrf-middleware");
    println!("==================================================");

    // Reset counters
    ALLOCATED.store(0, Ordering::SeqCst);
    DEALLOCATED.store(0, Ordering::SeqCst);

    let start_time = Instant::now();
    let (start_allocated, start_net) = get_memory_usage();

    // Test Double Submit Cookie Pattern
    let secret_key = b"test-secret-key-32-bytes-long!!!";
    let config = CsrfMiddlewareConfig::double_submit_cookie(secret_key).with_multipart(true);

    let app = test::init_service(
        App::new()
            .wrap(CsrfMiddleware::new(config))
            .route("/", web::get().to(handler))
            .route("/", web::post().to(post_handler)),
    )
    .await;

    println!("\nDouble Submit Cookie Pattern:");
    println!("----------------------------");

    // Perform multiple requests to measure memory usage
    let iterations = 100000;
    for i in 0..iterations {
        if i % 10000 == 0 {
            let (allocated, net) = get_memory_usage();
            println!(
                "After {} requests - Allocated: {} bytes, Net: {} bytes",
                i,
                allocated - start_allocated,
                net - start_net
            );
        }

        // GET request to fetch token
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&app, req).await;

        let token_cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == "csrf-token")
            .map(|c| c.into_owned())
            .unwrap();
        let pre_session_cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == "pre-session")
            .map(|c| c.into_owned());
        let body = test::read_body(resp).await;
        let token = String::from_utf8(body.to_vec()).unwrap();
        let token = token.strip_prefix("CSRF Token: ").unwrap();

        // POST request with received token
        let mut req = test::TestRequest::post()
            .uri("/")
            .insert_header(("X-CSRF-Token", token))
            .cookie(token_cookie);
        if let Some(pre_session) = pre_session_cookie {
            req = req.cookie(pre_session);
        }
        let req = req.to_request();
        let _resp = test::call_service(&app, req).await;
    }

    let end_time = Instant::now();
    let (end_allocated, end_net) = get_memory_usage();

    println!("\nFinal Results:");
    println!("--------------");
    println!("Total allocated: {} bytes", end_allocated - start_allocated);
    println!("Net memory usage: {} bytes", end_net - start_net);
    println!("Time elapsed: {:?}", end_time - start_time);
    println!(
        "Requests per second: {:.2}",
        (iterations * 2) as f64 / (end_time - start_time).as_secs_f64()
    );

    // Test Synchronizer Token Pattern if feature is enabled
#[cfg(feature = "session")]
    {
        println!("\n\nSynchronizer Token Pattern:");
        println!("---------------------------");

        ALLOCATED.store(0, Ordering::SeqCst);
        DEALLOCATED.store(0, Ordering::SeqCst);

        let start_time = Instant::now();
        let (start_allocated, start_net) = get_memory_usage();

        let config = CsrfMiddlewareConfig::synchronizer_token().with_multipart(true);

        let session_middleware = SessionMiddleware::builder(
            CookieSessionStore::default(),
            Key::generate()
        )
        .cookie_content_security(CookieContentSecurity::Private)
        .cookie_secure(true)
        .cookie_http_only(true)
        .cookie_same_site(actix_web::cookie::SameSite::Strict)
        .build();

        let app = test::init_service(
            App::new()
                .wrap(CsrfMiddleware::new(config))
                .wrap(session_middleware)
                .route("/", web::get().to(handler))
                .route("/", web::post().to(post_handler)),
        )
        .await;

        let iterations = 100000;
        for i in 0..iterations {
            if i % 10000 == 0 {
                let (allocated, net) = get_memory_usage();
                println!(
                    "After {} requests - Allocated: {} bytes, Net: {} bytes",
                    i,
                    allocated - start_allocated,
                    net - start_net
                );
            }

            // GET request to fetch token
            let req = test::TestRequest::get().uri("/").to_request();
            let resp = test::call_service(&app, req).await;

            let session_cookie = resp
                .response()
                .cookies()
                .find(|c| c.name() == "id")
                .map(|c| c.into_owned())
                .unwrap();
            let body = test::read_body(resp).await;
            let token = String::from_utf8(body.to_vec()).unwrap();
            let token = token.strip_prefix("CSRF Token: ").unwrap();

            // POST request with received token
            let req = test::TestRequest::post()
                .uri("/")
                .insert_header(("X-CSRF-Token", token))
                .cookie(session_cookie)
                .to_request();
            let _resp = test::call_service(&app, req).await;
        }

        let end_time = Instant::now();
        let (end_allocated, end_net) = get_memory_usage();

        println!("\nFinal Results:");
        println!("--------------");
        println!("Total allocated: {} bytes", end_allocated - start_allocated);
        println!("Net memory usage: {} bytes", end_net - start_net);
        println!("Time elapsed: {:?}", end_time - start_time);
        println!(
            "Requests per second: {:.2}",
            (iterations * 2) as f64 / (end_time - start_time).as_secs_f64()
        );
    }
}
