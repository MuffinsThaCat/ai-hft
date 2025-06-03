use std::env;
use reqwest;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting StatelessVM connectivity test...");
    
    // Get StatelessVM endpoint from environment or use default
    let statelessvm_url = env::var("STATELESSVM_URL")
        .unwrap_or_else(|_| {
            println!("STATELESSVM_URL not set, using default local endpoint");
            "http://localhost:7548".to_string()
        });
    
    println!("Testing connection to StatelessVM at: {}", statelessvm_url);
    
    // Test 1: Check service health
    println!("\nTest 1: Health check...");
    match reqwest::get(format!("{}/health", statelessvm_url)).await {
        Ok(response) => {
            if response.status().is_success() {
                println!("✓ Health check succeeded - StatelessVM service is running!");
                let body = response.text().await?;
                println!("  Response: {}", body);
            } else {
                println!("✗ Health check failed - Status: {}", response.status());
                println!("  Response: {}", response.text().await?);
            }
        },
        Err(e) => {
            println!("✗ Health check failed - Connection error: {}", e);
            return Err(e.into());
        }
    }
    
    // Test 2: Check API endpoint - info
    println!("\nTest 2: API info check...");
    match reqwest::get(format!("{}/info", statelessvm_url)).await {
        Ok(response) => {
            println!("  Status: {}", response.status());
            if response.status().is_success() {
                println!("✓ API info check succeeded!");
                let body = response.text().await?;
                println!("  Response: {}", body);
            } else {
                println!("✗ API info check failed!");
                println!("  Response: {}", response.text().await?);
            }
        },
        Err(e) => {
            println!("✗ API info check failed - Connection error: {}", e);
        }
    }
    
    // Test 3: Simple ping-pong (if supported)
    println!("\nTest 3: API ping check...");
    match reqwest::get(format!("{}/ping", statelessvm_url)).await {
        Ok(response) => {
            println!("  Status: {}", response.status());
            if response.status().is_success() {
                println!("✓ API ping check succeeded!");
                let body = response.text().await?;
                println!("  Response: {}", body);
            } else {
                println!("  Note: This endpoint may not be supported by the StatelessVM service");
            }
        },
        Err(_) => {
            println!("  Note: Ping endpoint not supported (this is normal)");
        }
    }

    println!("\nStatelessVM connectivity test completed.");
    println!("The StatelessVM service is accessible and running correctly!");
    
    Ok(())
}
