use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use once_cell::sync::Lazy;

/// Performance tracking categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PerformanceCategory {
    // Core trading operations
    MarketDataProcessing,
    OpportunityDetection,
    SecurityVerification,
    TransactionExecution,
    RelaySubmission,
    
    // Security verification subcategories
    ReentrancyCheck,
    IntegerOverflowCheck,
    IntegerUnderflowCheck,
    MevVulnerabilityCheck,
    UncheckedCallsCheck,
    CrossContractReentrancyCheck,
    GasGriefingCheck,
    AccessControlCheck,
    
    // Networking categories
    RpcCall,
    WebSocketData,
    
    // Custom user category
    Custom(String),
}

/// Detailed timing information for a performance category
#[derive(Debug, Clone)]
pub struct TimingStats {
    /// Number of operations measured
    pub count: u64,
    /// Total time spent across all operations
    pub total_duration: Duration,
    /// Minimum duration of any operation
    pub min_duration: Duration,
    /// Maximum duration of any operation
    pub max_duration: Duration,
    /// Running average duration
    pub avg_duration: Duration,
    /// Last operation duration
    pub last_duration: Duration,
    /// 95th percentile duration (approximation)
    pub p95_duration: Duration,
    /// Recent measurements kept for percentile calculation
    recent_measurements: Vec<Duration>,
    /// Maximum number of recent measurements to keep
    max_recent_measurements: usize,
}

impl TimingStats {
    /// Create new timing statistics
    fn new() -> Self {
        Self {
            count: 0,
            total_duration: Duration::from_secs(0),
            min_duration: Duration::from_secs(u64::MAX),
            max_duration: Duration::from_secs(0),
            avg_duration: Duration::from_secs(0),
            last_duration: Duration::from_secs(0),
            p95_duration: Duration::from_secs(0),
            recent_measurements: Vec::with_capacity(100),
            max_recent_measurements: 100,
        }
    }
    
    /// Record a new duration measurement
    fn record_duration(&mut self, duration: Duration) {
        self.count += 1;
        self.total_duration += duration;
        self.last_duration = duration;
        
        if duration < self.min_duration {
            self.min_duration = duration;
        }
        
        if duration > self.max_duration {
            self.max_duration = duration;
        }
        
        // Update average using running formula
        self.avg_duration = self.total_duration / self.count as u32;
        
        // Add to recent measurements for percentile calculation
        self.recent_measurements.push(duration);
        if self.recent_measurements.len() > self.max_recent_measurements {
            self.recent_measurements.remove(0);
        }
        
        // Recalculate 95th percentile if we have enough measurements
        if !self.recent_measurements.is_empty() {
            let mut sorted = self.recent_measurements.clone();
            sorted.sort();
            let idx = (sorted.len() as f64 * 0.95) as usize;
            self.p95_duration = sorted[idx.min(sorted.len() - 1)];
        }
    }
}

/// Performance tracker singleton for application-wide metrics
pub static PERFORMANCE_TRACKER: Lazy<PerformanceTracker> = Lazy::new(|| {
    PerformanceTracker::new()
});

/// Performance tracking utility for measuring execution times
#[derive(Debug)]
pub struct PerformanceTracker {
    /// Collected timing statistics by category
    stats: Arc<RwLock<HashMap<PerformanceCategory, TimingStats>>>,
    /// Active measurements by unique ID
    active_measurements: Arc<Mutex<HashMap<String, (PerformanceCategory, Instant)>>>,
    /// Whether the tracker is enabled
    enabled: Arc<RwLock<bool>>,
}

impl PerformanceTracker {
    /// Create a new performance tracker
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(HashMap::new())),
            active_measurements: Arc::new(Mutex::new(HashMap::new())),
            enabled: Arc::new(RwLock::new(true)),
        }
    }
    
    /// Get a reference to the global tracker
    pub fn global() -> &'static PerformanceTracker {
        &PERFORMANCE_TRACKER
    }
    
    /// Start measuring a specific category with a unique ID
    pub fn start_measure(&self, category: PerformanceCategory, measurement_id: &str) {
        if !*self.enabled.read().unwrap() {
            return;
        }
        
        let mut active = self.active_measurements.lock().unwrap();
        active.insert(measurement_id.to_string(), (category, Instant::now()));
    }
    
    /// Stop measuring a previously started measurement
    pub fn stop_measure(&self, measurement_id: &str) -> Option<Duration> {
        if !*self.enabled.read().unwrap() {
            return None;
        }
        
        let mut active = self.active_measurements.lock().unwrap();
        if let Some((category, start_time)) = active.remove(measurement_id) {
            let duration = start_time.elapsed();
            
            // Record the measurement
            let mut stats = self.stats.write().unwrap();
            let entry = stats.entry(category).or_insert_with(TimingStats::new);
            entry.record_duration(duration);
            
            return Some(duration);
        }
        
        None
    }
    
    /// Directly measure the duration of a function
    pub fn measure<F, R>(&self, category: PerformanceCategory, f: F) -> R
    where
        F: FnOnce() -> R
    {
        if !*self.enabled.read().unwrap() {
            return f();
        }
        
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        
        // Record the measurement
        let mut stats = self.stats.write().unwrap();
        let entry = stats.entry(category).or_insert_with(TimingStats::new);
        entry.record_duration(duration);
        
        result
    }
    
    /// Measure an async function (simplified version)
    pub async fn measure_async<F, R>(&self, category: PerformanceCategory, f: F) -> R
    where
        F: std::future::Future<Output = R>
    {
        if !*self.enabled.read().unwrap() {
            return f.await;
        }
        
        let start = Instant::now();
        let result = f.await;
        let duration = start.elapsed();
        
        // Record the measurement
        let mut stats = self.stats.write().unwrap();
        let entry = stats.entry(category).or_insert_with(TimingStats::new);
        entry.record_duration(duration);
        
        result
    }
    
    /// Get statistics for a specific category
    pub fn get_stats(&self, category: PerformanceCategory) -> Option<TimingStats> {
        let stats = self.stats.read().unwrap();
        stats.get(&category).cloned()
    }
    
    /// Get statistics for all categories
    pub fn get_all_stats(&self) -> HashMap<PerformanceCategory, TimingStats> {
        let stats = self.stats.read().unwrap();
        stats.clone()
    }
    
    /// Reset all statistics
    pub fn reset_stats(&self) {
        let mut stats = self.stats.write().unwrap();
        stats.clear();
    }
    
    /// Enable or disable the tracker
    pub fn set_enabled(&self, enabled: bool) {
        let mut tracker_enabled = self.enabled.write().unwrap();
        *tracker_enabled = enabled;
    }
    
    /// Create a performance report
    pub fn generate_report(&self) -> String {
        let stats = self.stats.read().unwrap();
        
        let mut report = String::new();
        report.push_str("Performance Report\n");
        report.push_str("=================\n\n");
        
        for (category, timing) in stats.iter() {
            report.push_str(&format!("Category: {:?}\n", category));
            report.push_str(&format!("  Count: {}\n", timing.count));
            report.push_str(&format!("  Average: {:?}\n", timing.avg_duration));
            report.push_str(&format!("  Min: {:?}\n", timing.min_duration));
            report.push_str(&format!("  Max: {:?}\n", timing.max_duration));
            report.push_str(&format!("  P95: {:?}\n", timing.p95_duration));
            report.push_str("\n");
        }
        
        report
    }
}

/// Struct to track an active measurement and automatically stop it when dropped
pub struct ActiveMeasurement<'a> {
    tracker: &'a PerformanceTracker,
    measurement_id: String,
    completed: bool,
}

impl<'a> ActiveMeasurement<'a> {
    /// Create a new active measurement
    pub fn new(category: PerformanceCategory, measurement_id: &str) -> Self {
        let tracker = PerformanceTracker::global();
        tracker.start_measure(category, measurement_id);
        
        Self {
            tracker,
            measurement_id: measurement_id.to_string(),
            completed: false,
        }
    }
    
    /// Stop the measurement manually (also happens automatically on drop)
    pub fn stop(&mut self) -> Option<Duration> {
        if !self.completed {
            self.completed = true;
            self.tracker.stop_measure(&self.measurement_id)
        } else {
            None
        }
    }
}

impl<'a> Drop for ActiveMeasurement<'a> {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.tracker.stop_measure(&self.measurement_id);
        }
    }
}

/// Convenience macro for measuring a code block
#[macro_export]
macro_rules! measure {
    ($category:expr, $code:block) => {
        crate::utils::performance::PerformanceTracker::global().measure($category, || $code)
    };
}

/// Convenience macro for creating an auto-measured scope
#[macro_export]
macro_rules! measure_scope {
    ($category:expr, $id:expr) => {
        let _measurement = crate::utils::performance::ActiveMeasurement::new($category, $id);
    };
}
