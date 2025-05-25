use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use ai_trading_agent::models::error::AgentResult;

#[tokio::main]
async fn main() -> AgentResult<()> {
    println!("Starting AI trading agent test...");
    
    // Start the mock relayer in a separate process
    println!("Starting mock bundle relayer...");
    let relayer = Command::new("cargo")
        .args(["run", "--bin", "mock_relayer"])
        .current_dir("/Users/talzisckind/Downloads/deployment/ai-trading-agent")
        .spawn()
        .expect("Failed to start mock relayer");
    
    println!("Mock relayer started, waiting for it to initialize...");
    sleep(Duration::from_secs(2)).await;
    
    // Now run the AI trading agent
    println!("Starting AI trading agent...");
    let status = Command::new("cargo")
        .args(["run", "--bin", "ai-trading-agent"])
        .current_dir("/Users/talzisckind/Downloads/deployment/ai-trading-agent")
        .status()
        .expect("Failed to run AI trading agent");
    
    println!("AI trading agent exited with status: {}", status);
    
    Ok(())
}
