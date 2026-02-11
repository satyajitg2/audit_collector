use audit_collector::collector::Collector;
use audit_collector::source::AuditSource;
#[cfg(target_os = "macos")]
use audit_collector::source::MacLogSource;
#[cfg(target_os = "linux")]
use audit_collector::source::LinuxAuditSource;
#[cfg(target_os = "windows")]
use audit_collector::source::WindowsEventSource;
use audit_collector::model::{FilterConfig, AuditEvent};
use crossbeam_channel::unbounded;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use axum::{
    routing::{get, post},
    Router,
    extract::State,
    response::sse::{Event, Sse},
    Json,
};
use tokio::sync::broadcast;
use futures::stream::Stream;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;


struct AppState {
    // Current filter configuration
    filter: Arc<RwLock<FilterConfig>>,
    // Broadcast channel to send events to SSE clients
    tx_events: broadcast::Sender<AuditEvent>,
    // Handle to the current collector thread (so we can restart it) - simplified: 
    // In this basic version we'll use a shared flag or channel to signal restart 
    // but since AuditSource interface is blocking/native thread based, 
    // we will rely on stopping the source (kill pid) and respecting the loop.
    source_arc: Arc<RwLock<Option<Arc<dyn AuditSource>>>>, // Keep reference to call stop()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Starting Audit Collector Server on http://localhost:9357");

    let (tx_events, _) = broadcast::channel(100);
    let state = Arc::new(AppState {
        filter: Arc::new(RwLock::new(FilterConfig::default())),
        tx_events: tx_events.clone(),
        source_arc: Arc::new(RwLock::new(None)),
    });

    // Start initial collector
    start_collector(state.clone());

    let app = Router::new()
        .route("/api/config", post(update_config).get(get_config))
        .route("/api/events", get(sse_handler))
        .fallback_service(ServeDir::new("ui/dist")) // Serve frontend
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9357").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn start_collector(state: Arc<AppState>) {
    // Stop existing if any
    if let Some(src) = state.source_arc.write().unwrap().take() {
        src.stop();
        // Give it a moment to die
        thread::sleep(Duration::from_millis(100));
    }

    let config = state.filter.read().unwrap().clone();
    println!("Restarting collector with config: {:?}", config);

    // Create source
    // Create source
    let source_result: anyhow::Result<Arc<dyn AuditSource>> = {
        #[cfg(target_os = "macos")]
        {
            MacLogSource::new(config).map(|s| Arc::new(s) as Arc<dyn AuditSource>)
        }
        #[cfg(target_os = "linux")]
        {
            LinuxAuditSource::new().map(|s| Arc::new(s) as Arc<dyn AuditSource>)
        }
        #[cfg(target_os = "windows")]
        {
            WindowsEventSource::new().map(|s| Arc::new(s) as Arc<dyn AuditSource>)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Err(anyhow::anyhow!("Unsupported OS"))
        }
    };

    let source = match source_result {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create source: {}", e);
            return;
        }
    };

    // Store source to stop later
    *state.source_arc.write().unwrap() = Some(source.clone());

    let (tx, rx) = unbounded();
    let collector = Collector::new(source.clone(), tx);
    let tx_broadcast = state.tx_events.clone();

    // Spawn collector thread
    thread::spawn(move || {
        // Collector run blocks
        // We need a way to forward from 'rx' (crossbeam) to 'tx_broadcast' (tokio broadcast)
        // Since collector.run() sends to 'tx', we can read from 'rx' here or 
        // actually Collector::run expects a Sender. 
        // We can just run the Collector in *this* thread? No, Collector::run has a loop.
        // We need to consume 'rx' and broadcast.
        
        // Let's spawn the collector Logic in another sub-thread or just use this one 
        // to Bridge crossbeam -> tokio broadcast.
        
        // Collector needs to run.
        let col_thread = thread::spawn(move || {
            if let Err(_e) = collector.run() {
               // eprintln!("Collector stopped: {:?}", e);
            }
        });

        // Bridge loop
        while let Ok(event) = rx.recv() {
            // Send to frontend
            let _ = tx_broadcast.send(event);
        }
        
        let _ = col_thread.join();
    });
}

// Handlers

async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<FilterConfig>,
) -> Json<String> {
    *state.filter.write().unwrap() = payload;
    // Restart collector
    start_collector(state.clone());
    Json("Config updated".to_string())
}

async fn get_config(State(state): State<Arc<AppState>>) -> Json<FilterConfig> {
    let config = state.filter.read().unwrap().clone();
    Json(config)
}

async fn sse_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, axum::BoxError>>> {
    let mut rx = state.tx_events.subscribe();
    
    let stream = async_stream::stream! {
        while let Ok(event) = rx.recv().await {
            yield Ok(Event::default().json_data(event).unwrap());
        }
    };

    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}
