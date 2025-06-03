use crate::relay::types::*;
use std::collections::HashMap;
use std::time::Duration;
use ethers::types::U256;

/// Metrics for the relay node and network
pub struct RelayMetrics {
    /// Total transactions submitted
    transactions_submitted: u64,
    /// Successful transactions
    successful_transactions: u64,
    /// Failed transactions
    failed_transactions: u64,
    /// Private transactions submitted
    private_transactions: u64,
    /// Public transactions submitted
    public_transactions: u64,
    /// Total bundles submitted
    bundles_submitted: u64,
    /// Successful bundles
    successful_bundles: u64,
    /// Failed bundles
    failed_bundles: u64,
    /// Average confirmation time (ms)
    average_confirmation_time: u64,
    /// Total gas saved through private routing
    gas_saved: U256,
    /// Latency by validator ID (ms)
    validator_latency: HashMap<String, u64>,
    /// Success rate by validator ID (percentage)
    validator_success_rate: HashMap<String, f64>,
}

impl RelayMetrics {
    /// Create a new metrics instance
    pub fn new() -> Self {
        Self {
            transactions_submitted: 0,
            successful_transactions: 0,
            failed_transactions: 0,
            private_transactions: 0,
            public_transactions: 0,
            bundles_submitted: 0,
            successful_bundles: 0,
            failed_bundles: 0,
            average_confirmation_time: 0,
            gas_saved: U256::zero(),
            validator_latency: HashMap::new(),
            validator_success_rate: HashMap::new(),
        }
    }
    
    /// Record a transaction submission
    pub fn record_transaction_submission(&mut self, is_private: bool, duration: Duration) {
        self.transactions_submitted += 1;
        
        if is_private {
            self.private_transactions += 1;
        } else {
            self.public_transactions += 1;
        }
    }
    
    /// Record a successful submission
    pub fn record_successful_submission(&mut self, is_private: bool) {
        self.successful_transactions += 1;
    }
    
    /// Record a failed submission
    pub fn record_failed_submission(&mut self, is_private: bool) {
        self.failed_transactions += 1;
    }
    
    /// Record bundle submission
    pub fn record_bundle_submission(&mut self) {
        self.bundles_submitted += 1;
    }
    
    /// Record successful bundle
    pub fn record_successful_bundle(&mut self) {
        self.successful_bundles += 1;
    }
    
    /// Record failed bundle
    pub fn record_failed_bundle(&mut self) {
        self.failed_bundles += 1;
    }
    
    /// Record confirmation time
    pub fn record_confirmation_time(&mut self, duration_ms: u64) {
        if self.average_confirmation_time == 0 {
            self.average_confirmation_time = duration_ms;
        } else {
            // Simple moving average
            self.average_confirmation_time = 
                (self.average_confirmation_time * 9 + duration_ms) / 10;
        }
    }
    
    /// Record gas saved
    pub fn record_gas_saved(&mut self, amount: U256) {
        self.gas_saved += amount;
    }
    
    /// Record validator latency
    pub fn record_validator_latency(&mut self, validator_id: &str, duration: Duration) {
        let duration_ms = duration.as_millis() as u64;
        
        match self.validator_latency.get_mut(validator_id) {
            Some(latency) => {
                // Simple moving average
                *latency = (*latency * 9 + duration_ms) / 10;
            },
            None => {
                self.validator_latency.insert(validator_id.to_string(), duration_ms);
            }
        }
    }
    
    /// Record validator success
    pub fn record_validator_success(&mut self, validator_id: &str, success: bool) {
        let success_rate = self.validator_success_rate
            .entry(validator_id.to_string())
            .or_insert(100.0);
            
        if success {
            // Slight increase for success (max 100%)
            *success_rate = (*success_rate * 0.95 + 100.0 * 0.05).min(100.0);
        } else {
            // More significant decrease for failures
            *success_rate = (*success_rate * 0.8).max(0.0);
        }
    }
    
    /// Get overall network statistics
    pub fn get_network_stats(&self) -> RelayNetworkStats {
        RelayNetworkStats {
            total_transactions_submitted: self.transactions_submitted,
            total_bundles_submitted: self.bundles_submitted,
            successful_transactions: self.successful_transactions,
            failed_transactions: self.failed_transactions,
            average_confirmation_time_ms: self.average_confirmation_time,
            average_latency_ms: self.calculate_average_latency(),
            total_gas_saved: self.gas_saved,
            total_validator_rewards: U256::zero(), // Not tracked in this version
        }
    }
    
    /// Calculate average latency across all validators
    fn calculate_average_latency(&self) -> u64 {
        if self.validator_latency.is_empty() {
            return 0;
        }
        
        let sum: u64 = self.validator_latency.values().sum();
        sum / self.validator_latency.len() as u64
    }
}
