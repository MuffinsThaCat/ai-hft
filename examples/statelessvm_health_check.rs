use log::{info, error};
use simple_logger::SimpleLogger;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger
    SimpleLogger::new().with_level(log::LevelFilter::Debug).init().unwrap();
    info!("Starting StatelessVM health check...");

    // Get StatelessVM URL from environment
    let statelessvm_url = env::var("STATELESSVM_URL").unwrap_or_else(|_| "http://localhost:7548".to_string());
    info!("Using StatelessVM URL: {}", statelessvm_url);
    
    // Create HTTP client
    let client = reqwest::Client::new();
    
    // Make a health check request
    info!("Making health check request to {}/health", statelessvm_url);
    let response = client.get(&format!("{}/health", statelessvm_url))
        .send()
        .await?;
        
    // Save the status code before consuming the response with text()
    let status = response.status();
    let body = response.text().await?;
    
    if status.is_success() {
        info!("✅ StatelessVM health check succeeded!");
        info!("Response: {}", body);
        Ok(())
    } else {
        error!("❌ StatelessVM health check failed with status: {}", status);
        error!("Response: {}", body);
        Err(format!("StatelessVM health check failed with status: {}", status).into())
    }
}
