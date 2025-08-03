use actix_csrf_middleware::{CsrfMiddleware, CsrfMiddlewareConfig, CsrfToken};
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, test};
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
    let config = CsrfMiddlewareConfig::double_submit_cookie(secret_key)
        .with_multipart(true);
    
    let app = test::init_service(
        App::new()
            .wrap(CsrfMiddleware::new(config))
            .route("/", web::get().to(handler))
            .route("/", web::post().to(post_handler))
    ).await;
    
    println!("\nDouble Submit Cookie Pattern:");
    println!("----------------------------");
    
    // Perform multiple requests to measure memory usage
    for i in 0..1000 {
        if i % 100 == 0 {
            let (allocated, net) = get_memory_usage();
            println!("After {} requests - Allocated: {} bytes, Net: {} bytes", 
                     i, allocated - start_allocated, net - start_net);
        }
        
        // GET request
        let req = test::TestRequest::get()
            .uri("/")
            .to_request();
        let _resp = test::call_service(&app, req).await;
        
        // POST request with CSRF token
        let req = test::TestRequest::post()
            .uri("/")
            .insert_header(("X-CSRF-Token", "test-token"))
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
    println!("Requests per second: {:.2}", 2000.0 / (end_time - start_time).as_secs_f64());
    
    // Test Synchronizer Token Pattern if feature is enabled
    #[cfg(feature = "session")]
    {
        println!("\n\nSynchronizer Token Pattern:");
        println!("---------------------------");
        
        ALLOCATED.store(0, Ordering::SeqCst);
        DEALLOCATED.store(0, Ordering::SeqCst);
        
        let start_time = Instant::now();
        let (start_allocated, start_net) = get_memory_usage();
        
        let config = CsrfMiddlewareConfig::synchronizer_token()
            .with_multipart(true);
        
        let app = test::init_service(
            App::new()
                .wrap(CsrfMiddleware::new(config))
                .route("/", web::get().to(handler))
                .route("/", web::post().to(post_handler))
        ).await;
        
        for i in 0..1000 {
            if i % 100 == 0 {
                let (allocated, net) = get_memory_usage();
                println!("After {} requests - Allocated: {} bytes, Net: {} bytes", 
                         i, allocated - start_allocated, net - start_net);
            }
            
            let req = test::TestRequest::get()
                .uri("/")
                .to_request();
            let _resp = test::call_service(&app, req).await;
            
            let req = test::TestRequest::post()
                .uri("/")
                .insert_header(("X-CSRF-Token", "test-token"))
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
        println!("Requests per second: {:.2}", 2000.0 / (end_time - start_time).as_secs_f64());
    }
}
