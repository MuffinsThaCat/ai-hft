use tokio::net::TcpListener;
use warp::{http::StatusCode, Filter, Rejection, Reply};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BundleRequest {
    transactions: Vec<String>,
    block_number: String,
    min_timestamp: Option<u64>,
    max_timestamp: Option<u64>,
    reverting_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BundleResponse {
    bundle_hash: String,
    inclusion_block: String,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatusResponse {
    bundle_hash: String,
    status: String,
    inclusion_block: Option<String>,
    error: Option<String>,
}

// In-memory store for bundle statuses
type Bundles = Arc<Mutex<HashMap<String, (String, u64)>>>;

#[tokio::main]
async fn main() {
    // Initialize bundle store
    let bundles: Bundles = Arc::new(Mutex::new(HashMap::new()));
    let bundles_clone = bundles.clone();

    // Start the bundle processor in a background task
    tokio::spawn(async move {
        loop {
            process_bundles(bundles_clone.clone()).await;
            sleep(Duration::from_secs(2)).await;
        }
    });

    // Set up the API routes
    let bundle_submission = warp::path!("api" / "v1" / "bundle")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_bundles(bundles.clone()))
        .and_then(handle_bundle_submission);

    let bundle_status = warp::path!("api" / "v1" / "bundle" / String / "status")
        .and(warp::get())
        .and(with_bundles(bundles.clone()))
        .and_then(handle_bundle_status);

    // Combine routes
    let routes = bundle_submission.or(bundle_status);

    println!("Starting mock bundle relayer on port 8545");
    warp::serve(routes).run(([127, 0, 0, 1], 8545)).await;
}

// Helper to pass bundles to handlers
fn with_bundles(bundles: Bundles) -> impl Filter<Extract = (Bundles,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || bundles.clone())
}

// Handle bundle submission
async fn handle_bundle_submission(
    request: BundleRequest,
    bundles: Bundles,
) -> Result<impl Reply, Rejection> {
    println!("Received bundle with {} transactions", request.transactions.len());
    
    // Generate a random bundle hash
    let bundle_hash = format!("0x{:016x}", rand::random::<u64>());
    
    // Store the bundle status (pending) and current timestamp
    {
        let mut bundles_map = bundles.lock().unwrap();
        bundles_map.insert(bundle_hash.clone(), ("pending".to_string(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()));
    }
    
    // Create response
    let response = BundleResponse {
        bundle_hash: bundle_hash.clone(),
        inclusion_block: request.block_number,
        status: "pending".to_string(),
    };
    
    println!("Created bundle with hash: {}", bundle_hash);
    Ok(warp::reply::json(&response))
}

// Handle bundle status request
async fn handle_bundle_status(
    bundle_hash: String,
    bundles: Bundles,
) -> Result<impl Reply, Rejection> {
    let bundles_map = bundles.lock().unwrap();
    
    if let Some((status, _)) = bundles_map.get(&bundle_hash) {
        let response = StatusResponse {
            bundle_hash: bundle_hash.clone(),
            status: status.clone(),
            inclusion_block: Some("0x1234".to_string()),
            error: None,
        };
        
        Ok(warp::reply::with_status(
            warp::reply::json(&response),
            StatusCode::OK
        ))
    } else {
        // Bundle not found
        let response = StatusResponse {
            bundle_hash,
            status: "unknown".to_string(),
            inclusion_block: None,
            error: Some("Bundle not found".to_string()),
        };
        
        Ok(warp::reply::with_status(
            warp::reply::json(&response),
            StatusCode::NOT_FOUND,
        ))
    }
}

// Process bundles and update their status
async fn process_bundles(bundles: Bundles) {
    let mut to_update = Vec::new();
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Find bundles to update
    {
        let bundles_map = bundles.lock().unwrap();
        for (hash, (status, timestamp)) in bundles_map.iter() {
            if status == "pending" {
                let age = current_time - timestamp;
                if age >= 5 {
                    // After 5 seconds, mark as confirmed
                    to_update.push((hash.clone(), "confirmed".to_string()));
                }
            }
        }
    }
    
    // Update bundle statuses
    if !to_update.is_empty() {
        let mut bundles_map = bundles.lock().unwrap();
        for (hash, new_status) in to_update {
            println!("Updating bundle {} status to {}", hash, new_status);
            if let Some((status, timestamp)) = bundles_map.get_mut(&hash) {
                *status = new_status;
            }
        }
    }
}
