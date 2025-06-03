use crate::security::verifier::SecurityVerifier;
use crate::statelessvm::client::{StatelessVmClient, StatelessTxRequest};
use uuid::Uuid;
use crate::strategies::manager::{StrategyManager, StrategyResult, ActionType};
use crate::utils::config::ExecutionConfig;
use ethers::prelude::*;
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{transaction::eip2718::TypedTransaction, Bytes, TransactionRequest, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
// Define SendError type alias for this module
type SendError = Box<dyn std::error::Error + Send + Sync>;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time;

// Interface to the Avalanche Bundle Relayer
#[derive(Debug)]
pub struct BundleRelayer {
    provider: Provider<Http>,
    wallet: LocalWallet,
    relayer_client: reqwest::Client,
    relayer_url: String,
    max_gas_price_gwei: u64,
    nonce_map: HashMap<Address, U256>,
}

// Bundle relayer API request/response types
#[derive(Debug, Serialize)]
struct BundleRequest {
    transactions: Vec<String>,       // Hex-encoded transaction data
    block_number: String,            // Target block number (hex)
    min_timestamp: Option<u64>,      // Optional minimum timestamp
    max_timestamp: Option<u64>,      // Optional maximum timestamp
    reverting_hashes: Vec<String>,   // Hashes that are allowed to revert
}

#[derive(Debug, Deserialize)]
struct BundleResponse {
    bundle_hash: String,
    inclusion_block: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct StatusResponse {
    bundle_hash: String,
    status: String,
    inclusion_block: Option<String>,
    error: Option<String>,
}

// Trading contracts ABI interfaces
#[derive(Debug, Clone)]
struct TraderJoeRouterV2 {
    address: Address,
    abi: ethers::abi::Abi,
    contract: ethers::contract::Contract<Provider<Http>>,
}

impl BundleRelayer {
    async fn new(
        relayer_url: &str,
        rpc_url: &str,
        wallet_key: &str,
        max_gas_price_gwei: u64,
    ) -> Result<Self, SendError> {
        // Connect to Avalanche C-Chain
        let provider = Provider::<Http>::try_from(rpc_url)?;
        
        // Set up wallet for signing transactions
        let wallet = if wallet_key.is_empty() {
            // Generate random wallet for development if no key provided
            LocalWallet::new(&mut rand::thread_rng())
        } else {
            // Use provided private key
            wallet_key.parse::<LocalWallet>()?
        };
        
        // Initialize HTTP client for relayer API
        let relayer_client = reqwest::Client::new();
        
        Ok(Self {
            provider,
            wallet,
            relayer_client,
            relayer_url: relayer_url.to_string(),
            max_gas_price_gwei,
            nonce_map: HashMap::new(),
        })
    }
    
    // Get the next nonce for a wallet address
    async fn get_next_nonce(&mut self, address: Address) -> Result<U256, SendError> {
        // Check if we have a nonce in our map
        if let Some(nonce) = self.nonce_map.get(&address) {
            // Increment the stored nonce
            let next_nonce = *nonce + U256::from(1);
            self.nonce_map.insert(address, next_nonce);
            return Ok(next_nonce);
        }
        
        // If not, get the current nonce from the blockchain
        let current_nonce = self.provider.get_transaction_count(address, None).await?;
        self.nonce_map.insert(address, current_nonce);
        Ok(current_nonce)
    }
    
    // Create a DEX swap transaction
    async fn create_swap_transaction(
        &mut self,
        action_type: &ActionType,
        asset: &str,
        amount: &str,
    ) -> Result<String, SendError> {
        // Parse the amount (remove non-numeric parts)
        let amount_str = amount.split_whitespace().next().unwrap_or("0");
        let amount_float = amount_str.parse::<f64>().unwrap_or(0.0);
        
        // Define the available router addresses
        let traderjoe_router = "0x18556DA13313f3532c54711497A8FedAC273220E".parse::<Address>()?; // TraderJoe V2.2 LBRouter
        let pharaoh_router = "0x062c62cA66E50Cfe277A95564Fe5bB504db1Fab8".parse::<Address>()?; // Pharaoh SwapRouter
        
        // Use TraderJoe router by default
        // In a real implementation, we could pass target_address as a parameter to this function
        let (router_address, is_pharaoh) = (traderjoe_router, false);
        
        // For more sophisticated routing logic in the future, add a parameter to this function
        // and handle router selection based on that parameter
        
        // Real token addresses on Avalanche C-Chain
        let token_address_str = match asset.to_uppercase().as_str() {
            // Native token
            "AVAX" => "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE", // Native AVAX
            "WAVAX" => "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7", // Wrapped AVAX
            
            // Stablecoins
            "USDC" => "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", // USDC on Avalanche
            "USDC.E" => "0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664", // USDC.e on Avalanche
            "USDT" => "0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7", // USDT on Avalanche
            "USDT.E" => "0xc7198437980c041c805A1EDcbA50c1Ce5db95118", // USDT.e on Avalanche
            "DAI.E" => "0xd586E7F844cEa2F87f50152665BCbc2C279D8d70", // DAI.e on Avalanche
            
            // Ethereum tokens bridged to Avalanche
            "ETH" => "0x49D5c2BdFfac6CE2BFdB6640F4F80f226bc10bAB", // WETH.e on Avalanche
            "WETH.E" => "0x49D5c2BdFfac6CE2BFdB6640F4F80f226bc10bAB", // WETH.e on Avalanche
            "BTC.B" => "0x152b9d0FdC40C096757F570A51E494bd4b943E50", // BTC.b on Avalanche
            "WBTC.E" => "0x50b7545627a5162F82A992c33b87aDc75187B218", // WBTC.e on Avalanche
            
            // TraderJoe tokens
            "JOE" => "0x6e84a6216eA6dACC71eE8E6b0a5B7322EEbC0fDd", // JOE token
            
            // Other popular tokens
            "LINK.E" => "0x5947BB275c521040051D82396192181b413227A3", // LINK.e on Avalanche
            "AAVE.E" => "0x63a72806098Bd3D9520cC43356dD78afe5D386D9", // AAVE.e on Avalanche
            
            _ => {
                return Err(format!("Unsupported token: {}", asset).into());
            }
        };
        
        // Convert token address string to Address type
        let token_address = Address::from_str(token_address_str).map_err(|e| Box::new(e) as SendError)?;
        
        // Get the current wallet address
        let wallet_address = self.wallet.address();
        
        // Get the next nonce for this wallet
        let nonce = self.get_next_nonce(wallet_address).await?;
        
        // Get current gas prices
        let gas_price = U256::from(self.max_gas_price_gwei) * U256::exp10(9); // Convert Gwei to Wei
        
        // Create a transaction based on the action type
        let tx = match action_type {
            ActionType::Buy => {
                // Buying a token with another token on TraderJoe or Pangolin DEX
                let token_in = token_address;
                let wavax = H160::from_str("0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7").map_err(|e| Box::new(e) as SendError)?; // WAVAX on Avalanche
                let path = vec![token_in, wavax]; // From token to WAVAX
                
                // Calculate deadline (5 minutes from now)
                let deadline = U256::from(chrono::Utc::now().timestamp() + 300);
                
                // Parse amount to swap
                let amount_in = U256::from_dec_str(amount_str).map_err(|e| Box::new(e) as SendError)?;
                
                // Minimum amount out (with 0.5% slippage tolerance)
                let amount_out_min = amount_in.checked_mul(U256::from(995)).unwrap_or_default().checked_div(U256::from(1000)).unwrap_or_default();
                
                // Encode router function: swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)
                let router = router_address;
                let recipient = self.wallet.address();
                
                // Create function selector based on the router
                let func_selector = if is_pharaoh {
                    // Pharaoh/Uniswap V3-style router uses exactInputSingle(ExactInputSingleParams)
                    [0x41, 0x4b, 0xf3, 0x89] // Function selector for exactInputSingle
                } else {
                    // TraderJoe V2.2 router uses swapExactTokensForTokens(uint256,uint256,Path,address,uint256)
                    [0xc1, 0x95, 0xc6, 0x1e] // Function selector for V2.2 router
                };
                
                // Encode parameters based on the router type
                let mut encoded = if is_pharaoh {
                    // Pharaoh/Uniswap V3-style router uses exactInputSingle with a struct parameter
                    // struct ExactInputSingleParams {
                    //    address tokenIn;
                    //    address tokenOut;
                    //    uint24 fee; // Pool fee (3000 = 0.3%)
                    //    address recipient;
                    //    uint256 deadline;
                    //    uint256 amountIn;
                    //    uint256 amountOutMinimum;
                    //    uint160 sqrtPriceLimitX96; // 0 for no price limit
                    // }
                    
                    // Common fee tier is 3000 (0.3%)
                    let fee = U256::from(3000);
                    
                    // No price limit (0 for infinite)
                    let sqrt_price_limit_x96 = U256::zero();
                    
                    // Create the ExactInputSingleParams struct
                    let params = ethers::abi::Token::Tuple(vec![
                        ethers::abi::Token::Address(path[0]), // tokenIn
                        ethers::abi::Token::Address(path[1]), // tokenOut
                        ethers::abi::Token::Uint(fee), // fee
                        ethers::abi::Token::Address(recipient), // recipient
                        ethers::abi::Token::Uint(deadline), // deadline
                        ethers::abi::Token::Uint(amount_in), // amountIn
                        ethers::abi::Token::Uint(amount_out_min), // amountOutMinimum
                        ethers::abi::Token::Uint(sqrt_price_limit_x96), // sqrtPriceLimitX96
                    ]);
                    
                    ethers::abi::encode(&[params])
                } else {
                    // TraderJoe V2.2 LBRouter encoding
                    // Path struct has pairBinSteps (uint16[]), versions (uint8[]), and tokenPath (IERC20[])
                    
                    // Creating Path struct components
                    // For simplicity, using default binStep of 15 which is common on TraderJoe
                    let bin_steps = vec![ethers::abi::Token::Uint(U256::from(15))];
                    
                    // Version 2.2 for all pairs
                    let versions = vec![ethers::abi::Token::Uint(U256::from(2))]; // Version V2_2
                    
                    // Path struct
                    let path_struct = ethers::abi::Token::Tuple(vec![
                        ethers::abi::Token::Array(bin_steps),
                        ethers::abi::Token::Array(versions),
                        ethers::abi::Token::Array(path.iter().map(|&addr| ethers::abi::Token::Address(addr)).collect()),
                    ]);
                    
                    ethers::abi::encode(&[
                        ethers::abi::Token::Uint(amount_in),
                        ethers::abi::Token::Uint(amount_out_min),
                        path_struct,
                        ethers::abi::Token::Address(recipient),
                        ethers::abi::Token::Uint(deadline),
                    ])
                };
                
                // Combine selector and encoded parameters
                let mut data = Vec::with_capacity(4 + encoded.len());
                data.extend_from_slice(&func_selector);
                data.append(&mut encoded);
                
                TransactionRequest::new()
                    .to(router)
                    .value(U256::zero()) // No AVAX sent for token->token swaps
                    .gas_price(gas_price)
                    .nonce(nonce)
                    .data(Bytes::from(data))
            },
            ActionType::Sell => {
                // Selling WAVAX for another token on TraderJoe or Pangolin DEX
                let wavax = Address::from_str("0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7").map_err(|e| Box::new(e) as SendError)?; // WAVAX on Avalanche
                let token_out = token_address;
                let path = vec![wavax, token_out]; // From WAVAX to token
                
                // Calculate deadline (5 minutes from now)
                let deadline = U256::from(chrono::Utc::now().timestamp() + 300);
                
                // Parse amount to swap
                let amount_in = U256::from_dec_str(amount_str).map_err(|e| Box::new(e) as SendError)?;
                
                // Minimum amount out (with 0.5% slippage tolerance)
                let amount_out_min = amount_in.checked_mul(U256::from(995)).unwrap_or_default().checked_div(U256::from(1000)).unwrap_or_default();
                
                // Encode router function: swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)
                let router = router_address;
                let recipient = self.wallet.address();
                
                // Create function selector based on the router
                let func_selector = if is_pharaoh {
                    // Pharaoh/Uniswap V3-style router uses exactInputSingle(ExactInputSingleParams)
                    [0x41, 0x4b, 0xf3, 0x89] // Function selector for exactInputSingle
                } else {
                    // TraderJoe V2.2 router uses swapExactTokensForTokens(uint256,uint256,Path,address,uint256)
                    [0xc1, 0x95, 0xc6, 0x1e] // Function selector for V2.2 router
                };
                
                // Encode parameters based on the router type
                let mut encoded = if is_pharaoh {
                    // Pharaoh/Uniswap V3-style router uses exactInputSingle with a struct parameter
                    // struct ExactInputSingleParams {
                    //    address tokenIn;
                    //    address tokenOut;
                    //    uint24 fee; // Pool fee (3000 = 0.3%)
                    //    address recipient;
                    //    uint256 deadline;
                    //    uint256 amountIn;
                    //    uint256 amountOutMinimum;
                    //    uint160 sqrtPriceLimitX96; // 0 for no price limit
                    // }
                    
                    // Common fee tier is 3000 (0.3%)
                    let fee = U256::from(3000);
                    
                    // No price limit (0 for infinite)
                    let sqrt_price_limit_x96 = U256::zero();
                    
                    // Create the ExactInputSingleParams struct
                    let params = ethers::abi::Token::Tuple(vec![
                        ethers::abi::Token::Address(path[0]), // tokenIn
                        ethers::abi::Token::Address(path[1]), // tokenOut
                        ethers::abi::Token::Uint(fee), // fee
                        ethers::abi::Token::Address(recipient), // recipient
                        ethers::abi::Token::Uint(deadline), // deadline
                        ethers::abi::Token::Uint(amount_in), // amountIn
                        ethers::abi::Token::Uint(amount_out_min), // amountOutMinimum
                        ethers::abi::Token::Uint(sqrt_price_limit_x96), // sqrtPriceLimitX96
                    ]);
                    
                    ethers::abi::encode(&[params])
                } else {
                    // TraderJoe V2.2 LBRouter encoding
                    // Path struct has pairBinSteps (uint16[]), versions (uint8[]), and tokenPath (IERC20[])
                    
                    // Creating Path struct components
                    // For simplicity, using default binStep of 15 which is common on TraderJoe
                    let bin_steps = vec![ethers::abi::Token::Uint(U256::from(15))];
                    
                    // Version 2.2 for all pairs
                    let versions = vec![ethers::abi::Token::Uint(U256::from(2))]; // Version V2_2
                    
                    // Path struct
                    let path_struct = ethers::abi::Token::Tuple(vec![
                        ethers::abi::Token::Array(bin_steps),
                        ethers::abi::Token::Array(versions),
                        ethers::abi::Token::Array(path.iter().map(|&addr| ethers::abi::Token::Address(addr)).collect()),
                    ]);
                    
                    ethers::abi::encode(&[
                        ethers::abi::Token::Uint(amount_in),
                        ethers::abi::Token::Uint(amount_out_min),
                        path_struct,
                        ethers::abi::Token::Address(recipient),
                        ethers::abi::Token::Uint(deadline),
                    ])
                };
                
                // Combine selector and encoded parameters
                let mut data = Vec::with_capacity(4 + encoded.len());
                data.extend_from_slice(&func_selector);
                data.append(&mut encoded);
                
                TransactionRequest::new()
                    .to(router)
                    .value(U256::zero()) // No ETH sent for token->token swaps
                    .gas_price(gas_price)
                    .nonce(nonce)
                    .data(Bytes::from(data))
            },
        };
        
        // Convert to EIP-1559 transaction
        let typed_tx: TypedTransaction = tx.into();
        
        // Sign the transaction
        let signature = self.wallet.sign_transaction(&typed_tx).await?;
        
        // Serialize the signed transaction
        let signed_tx = typed_tx.rlp_signed(&signature);
        
        // Return the hex-encoded transaction
        Ok(format!("0x{}", hex::encode(signed_tx)))
    }
    
    // Bundle transactions and submit to relayer
    async fn bundle_transactions(&self, txs: &[String]) -> Result<String, SendError> {
        // Get current block number for targeting
        let current_block = self.provider.get_block_number().await?;
        let target_block = current_block + 2; // Target 2 blocks ahead
        
        // Create bundle request
        let bundle_request = BundleRequest {
            transactions: txs.to_vec(),
            block_number: format!("0x{:x}", target_block),
            min_timestamp: None,
            max_timestamp: None,
            reverting_hashes: Vec::new(), // Allow no reverts for safety
        };
        
        // Submit bundle to relayer
        let response = self.relayer_client
            .post(format!("{}/api/v1/bundle", self.relayer_url))
            .json(&bundle_request)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(format!("Failed to submit bundle: {}", response.status()).into());
        }
        
        let bundle_response: BundleResponse = response.json().await?;
        Ok(bundle_response.bundle_hash)
    }
}

// The execution engine coordinates between strategies and the stateless VM
pub struct ExecutionEngine {
    strategy_manager: Arc<Mutex<StrategyManager>>,
    relayer: BundleRelayer,
    security_verifier: SecurityVerifier,
    stateless_client: Arc<Mutex<StatelessVmClient>>,
    config: ExecutionConfig,
}

impl ExecutionEngine {
    pub async fn new(
        config: &ExecutionConfig,
        strategy_manager: Arc<Mutex<StrategyManager>>,
        security_verifier: SecurityVerifier,
    ) -> Result<Self, SendError> {
        // Initialize the bundle relayer with Avalanche configuration
        let relayer = BundleRelayer::new(
            &config.relayer_url,
            &config.avalanche_rpc_url, // Avalanche C-Chain RPC URL
            &config.wallet_key,
            config.max_gas_price_gwei,
        ).await?;
        
        // Log the connection to Avalanche network
        println!("Connected to Avalanche C-Chain at {}", config.avalanche_rpc_url);
        
        // Initialize the stateless VM client
        let stateless_client = Arc::new(Mutex::new(StatelessVmClient::new(&config.stateless_vm_url)));
        
        Ok(Self {
            strategy_manager,
            relayer,
            security_verifier,
            stateless_client,
            config: config.clone(),
        })
    }
    
    pub async fn run(&mut self) -> Result<(), SendError> {
        println!("Starting AI Trading Agent execution engine...");
        
        // Main execution loop - check for new strategies every few seconds
        let mut interval = time::interval(Duration::from_secs(5));
        
        loop {
            interval.tick().await;
            
            // Generate a new strategy
            let strategy_option = {
                // Lock the strategy manager only for this scope
                let mut strategy_manager = self.strategy_manager.lock().unwrap();
                strategy_manager.generate_strategy().await
            };
            
            match strategy_option {
                Ok(Some(strategy)) => {
                    println!("Generated strategy with confidence score: {}", strategy.confidence_score);
                    
                    // Check if we should execute this strategy
                    let should_execute = {
                        // Lock the strategy manager only for this scope
                        let mut strategy_manager = self.strategy_manager.lock().unwrap();
                        strategy_manager.should_execute_strategy(&strategy)
                    };
                    
                    if should_execute {
                        // Execute the strategy
                        // Execute the strategy
                        let strategy_result = self.execute_strategy(&strategy).await;
                        if strategy_result.is_ok() {
                            let bundle_hash = strategy_result.unwrap();
                            println!("Successfully executed strategy, bundle hash: {}", bundle_hash);
                            
                            // Monitor bundle status
                            self.monitor_bundle_status(&bundle_hash).await?
                        } else if let Err(err) = strategy_result {
                            eprintln!("Failed to execute strategy: {}", err);
                        }
                    } else {
                        println!("Strategy confidence too low, not executing");
                    }
                },
                Ok(None) => {
                    // No viable strategy found this cycle
                    println!("No viable trading strategy found this cycle");
                },
                Err(e) => {
                    eprintln!("Failed to generate strategy: {}", e);
                }
            }
        }
    }

    pub async fn execute_strategy(&mut self, strategy: &crate::strategies::manager::StrategyResult) -> Result<Box<str>, SendError> {
        println!("Executing strategy on Avalanche C-Chain: {}", strategy.strategy);

        // Avalanche C-Chain has chain ID 43114
        const AVALANCHE_CHAIN_ID: u64 = 43114;

        // Verify contracts for security before interacting
        // For simplicity, assuming all interactions are with known DEX contracts
        // In a real implementation, you would verify each contract you interact with
        let trader_joe_router = "0x18556DA13313f3532c54711497A8FedAC273220E"; // Updated to TraderJoe V2.2 LBRouter
        let vulnerabilities = self.security_verifier.verify_contract(trader_joe_router).await?;

        
        if !vulnerabilities.is_empty() {
            for vuln in &vulnerabilities {
                eprintln!("Warning: Security vulnerability found in contract {}: {:?}", 
                    trader_joe_router, vuln.vulnerability_type);
            }
            // Optionally abort if high-severity vulnerabilities are found
        }
        
        // Create transactions for each action in the strategy
        let mut transactions = Vec::new();
        for action in &strategy.actions {
            // Get wallet information for the transaction
            let wallet = LocalWallet::from_str(&self.config.wallet_key)?
                .with_chain_id(43114u64); // Avalanche C-Chain
            let wallet_address = wallet.address();
            
            // Security verification is now configured using individual boolean flags
            // in the SecurityVerificationRequest struct
            
            // Verify transaction safety using stateless VM
            let is_safe = self.security_verifier.verify_transaction_params(
                &wallet_address.to_string(),
                &action.target_address,
                &action.amount.to_string(),
                &action.action_data,
                "500000", // gas limit
                "20",     // gas price in gwei
            ).await?;
            
            if !is_safe {
                return Err(format!("Security verification failed for action: {:?}", action).into());
            }
            
            // Execute the transaction through stateless VM
            let tx_request = StatelessTxRequest {
                from: wallet_address.to_string(),
                to: action.target_address.clone(),
                value: action.amount.to_string(),
                data: action.action_data.clone(),
                gas_limit: "500000".to_string(),
                gas_price: "20".to_string(), // Use a fixed gas price for now
                security_verification: crate::statelessvm::client::SecurityVerificationRequest {
                    address: action.target_address.clone(),
                    enabled: true,
                    max_risk_score: self.config.max_risk_score,
                    verify_reentrancy: true,
                    verify_integer_underflow: true,
                    verify_integer_overflow: true,
                    verify_unchecked_calls: true,
                    verify_upgradability: true,
                    verify_mev_vulnerability: true,
                    verify_cross_contract_reentrancy: true,
                    verify_precision_loss: true,
                    verify_gas_griefing: true,
                },
                bundle_id: Some(format!("engine-{}", uuid::Uuid::new_v4())),
            };
            
            // Execute through stateless VM first to validate
            let stateless_response = {
                let mut client = self.stateless_client.lock().unwrap();
                client.execute_transaction(tx_request).await?
            };
                
            if stateless_response.status != "success" {
                return Err(format!("StatelessVM execution failed: {}", 
                    stateless_response.error.unwrap_or_else(|| "Unknown error".to_string())).into());
            }
            
            // After stateless VM validation, create real transaction
            // Use the action_type directly as it's already manager::ActionType
            let manager_action_type = &action.action_type;
            
            let tx = self.relayer.create_swap_transaction(
                &manager_action_type,
                &action.asset,
                &action.amount.to_string(),
            ).await?;
            
            transactions.push(tx);
        }
        
        // 2. Bundle and submit transactions
        let bundle_hash = self.relayer.bundle_transactions(&transactions).await?;
        
        // 3. Return bundle hash for monitoring
        Ok(bundle_hash.into_boxed_str())
    }    
        
    pub async fn monitor_bundle_status(&self, bundle_hash: &str) -> Result<(), SendError> {
        println!("Monitoring bundle status: {}", bundle_hash);
        
        // Initial delay before checking
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        
        // Check bundle status every 10 seconds until included or failed
        let mut attempts = 0;
        loop {
            let bundle_info = self.get_bundle_info(bundle_hash).await?;
            
            if let Some(status) = bundle_info.get("status") {
                let status_str = status.as_str().unwrap_or("unknown");
                println!("Bundle status: {}", status_str);
                
                if status_str == "included" {
                    println!("Bundle was successfully included in a block!");
                    return Ok(());
                } else if status_str == "failed" || status_str == "cancelled" {
                    return Err(format!("Bundle failed with status: {}", status_str).into());
                }
            }
            
            attempts += 1;
            if attempts > 12 { // 2 minutes max (12 * 10 seconds)
                return Err("Bundle inclusion timed out".into());
            }
            
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }
    }
    
    // Get a clone of the HTTP client for use in async tasks
    pub fn get_client_clone(&self) -> reqwest::Client {
        reqwest::Client::new()
    }
    
    // Helper method to get bundle information
    pub async fn get_bundle_info(&self, bundle_hash: &str) -> Result<serde_json::Value, SendError> {
        let client = reqwest::Client::new();
        let url = format!("https://relay.avax.network/bundles/{}", bundle_hash);

        let resp = client.get(&url)
            .header("Content-Type", "application/json")
            .send().await?
            .json::<serde_json::Value>().await?;

        Ok(resp)
    }
}
