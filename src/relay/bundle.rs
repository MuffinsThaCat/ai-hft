use crate::relay::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{debug, info, warn, error};
use std::time::{SystemTime, UNIX_EPOCH};
use ethers::types::U256;

/// Manager for transaction bundles
pub struct BundleManager {
    /// Maximum number of transactions in a bundle
    max_bundle_size: usize,
    /// Active bundles
    bundles: Arc<RwLock<HashMap<String, TransactionBundle>>>,
}

impl BundleManager {
    /// Create a new bundle manager
    pub fn new(max_bundle_size: usize) -> Self {
        Self {
            max_bundle_size,
            bundles: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Register a new bundle
    pub async fn register_bundle(&self, bundle: TransactionBundle) -> Result<(), RelayError> {
        let bundle_id = bundle.bundle_id.clone();
        
        if bundle.transactions.len() > self.max_bundle_size {
            return Err(format!("Bundle size exceeds maximum: {} > {}", 
                bundle.transactions.len(), self.max_bundle_size).into());
        }
        
        let mut bundles = self.bundles.write().await;
        if bundles.contains_key(&bundle_id) {
            return Err(format!("Bundle with ID {} already exists", bundle_id).into());
        }
        
        bundles.insert(bundle_id.clone(), bundle);
        debug!("Registered new bundle {}", bundle_id);
        
        Ok(())
    }
    
    /// Get a bundle by ID
    pub async fn get_bundle(&self, bundle_id: &str) -> Result<TransactionBundle, RelayError> {
        let bundles = self.bundles.read().await;
        
        bundles.get(bundle_id)
            .cloned()
            .ok_or_else(|| format!("Bundle {} not found", bundle_id).into())
    }
    
    /// Update bundle status
    pub async fn update_bundle_status(
        &self,
        bundle_id: &str,
        status: BundleStatus,
        submitted_at: Option<u64>,
        confirmed_at: Option<u64>,
    ) -> Result<(), RelayError> {
        let mut bundles = self.bundles.write().await;
        
        if let Some(bundle) = bundles.get_mut(bundle_id) {
            bundle.status = status.clone();
            
            if let Some(submitted) = submitted_at {
                bundle.timestamps.submitted_at = Some(submitted);
            }
            
            if let Some(confirmed) = confirmed_at {
                bundle.timestamps.confirmed_at = Some(confirmed);
            }
            
            debug!("Updated bundle {} status to {:?}", bundle_id, status);
            Ok(())
        } else {
            Err(format!("Bundle {} not found", bundle_id).into())
        }
    }
    
    /// Clean up expired bundles
    pub async fn clean_expired_bundles(&self) -> Result<usize, RelayError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        let mut bundles = self.bundles.write().await;
        let initial_count = bundles.len();
        
        // Remove expired bundles
        bundles.retain(|_, bundle| {
            if bundle.timestamps.expires_at <= now {
                match bundle.status {
                    BundleStatus::Confirmed | BundleStatus::Failed(_) | BundleStatus::Rejected(_) => {
                        // Already in terminal state, can be removed
                        false
                    },
                    _ => {
                        // Not in terminal state but expired, update status and remove
                        debug!("Bundle {} expired", bundle.bundle_id);
                        true
                    }
                }
            } else {
                // Not expired, keep
                true
            }
        });
        
        let removed = initial_count - bundles.len();
        if removed > 0 {
            debug!("Cleaned up {} expired bundles", removed);
        }
        
        Ok(removed)
    }
    
    /// Create a new optimized bundle from transactions
    pub async fn create_optimized_bundle(
        &self,
        transactions: Vec<EncryptedTransaction>,
        miner_reward: Option<U256>,
    ) -> Result<String, RelayError> {
        if transactions.is_empty() {
            return Err("Cannot create empty bundle".into());
        }
        
        if transactions.len() > self.max_bundle_size {
            return Err(format!("Too many transactions for bundle: {} > {}", 
                transactions.len(), self.max_bundle_size).into());
        }
        
        // Generate bundle ID
        let bundle_id = format!("bundle-{}", uuid::Uuid::new_v4());
        
        // Create bundle
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        let bundle = TransactionBundle {
            bundle_id: bundle_id.clone(),
            transactions,
            miner_reward,
            target_block: None,
            timestamps: BundleTimestamps {
                created_at: now,
                submitted_at: None,
                confirmed_at: None,
                expires_at: now + 120, // 2 minute expiration
            },
            status: BundleStatus::Created,
        };
        
        // Register bundle
        self.register_bundle(bundle).await?;
        
        Ok(bundle_id)
    }
}
