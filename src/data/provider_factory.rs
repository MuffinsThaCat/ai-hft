use crate::data::provider::{DataProvider, SendError};
use crate::data::ccip_provider::CCIPDataProvider;
use crate::utils::config::DataConfig;
use std::sync::Arc;
use log::{info, warn, error};

// Define a common interface for all data providers
#[async_trait::async_trait]
pub trait MarketDataProvider: Send + Sync + std::fmt::Debug {
    async fn get_token_price(&self, token_symbol: &str) -> Result<f64, SendError>;
    async fn get_market_data(&self, symbol: &str) -> Result<crate::data::provider::MarketData, SendError>;
    async fn get_dex_pair(&self, dex: &str, pair_address: &str) -> Result<crate::data::provider::DEXPair, SendError>;
    async fn get_gas_prices(&self) -> Result<crate::data::provider::GasInfo, SendError>;
}

// Implement the trait for the original DataProvider
#[async_trait::async_trait]
impl MarketDataProvider for DataProvider {
    async fn get_token_price(&self, token_symbol: &str) -> Result<f64, SendError> {
        self.get_token_price(token_symbol).await
    }
    
    async fn get_market_data(&self, symbol: &str) -> Result<crate::data::provider::MarketData, SendError> {
        self.get_market_data(symbol).await
    }
    
    async fn get_dex_pair(&self, dex: &str, pair_address: &str) -> Result<crate::data::provider::DEXPair, SendError> {
        self.get_dex_pair(dex, pair_address).await
    }
    
    async fn get_gas_prices(&self) -> Result<crate::data::provider::GasInfo, SendError> {
        self.get_gas_prices().await
    }
}

// CCIPDataProvider trait implementation is in ccip_provider.rs

// Factory to create the appropriate provider based on configuration
pub async fn create_data_provider(config: &DataConfig) -> Result<Arc<dyn MarketDataProvider>, SendError> {
    // Determine provider type from config
    let provider_type = config.provider_type.as_deref().unwrap_or("coingecko");
    
    match provider_type {
        "ccip" => {
            info!("Creating Chainlink CCIP data provider");
            let provider = CCIPDataProvider::new(config).await?;
            Ok(provider as Arc<dyn MarketDataProvider>)
        },
        "coingecko" | _ => {
            info!("Creating CoinGecko data provider");
            let provider = DataProvider::new(config).await?;
            Ok(provider as Arc<dyn MarketDataProvider>)
        }
    }
}
