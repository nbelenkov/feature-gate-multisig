/// Application constants for consistent configuration across modules

// Compute budget constants
pub const DEFAULT_COMPUTE_UNITS: u32 = 300_000;
pub const DEFAULT_PRIORITY_FEE: u64 = 5000;
pub const CREATE_MULTISIG_COMPUTE_UNITS: u32 = 50_000;

// Program IDs
pub const SQUADS_PROGRAM_ID_STR: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

// Transaction retry constants (optimized for ~10 second max retry window)
pub const MAX_TX_RETRIES: usize = 5;
pub const BASE_RETRY_DELAY_MS: u64 = 500;

// Confirmation constants
pub const CONFIRMATION_TIMEOUT_MS: u64 = 30_000; // 30 seconds
pub const CONFIRMATION_POLL_INTERVAL_MS: u64 = 1000; // 1 second

// Account data retry constants
pub const MAX_ACCOUNT_RETRIES: usize = 3;
pub const BASE_ACCOUNT_RETRY_DELAY_MS: u64 = 500;

// Default network URLs
pub const DEFAULT_DEVNET_URL: &str = "https://api.devnet.solana.com";
pub const DEFAULT_MAINNET_URL: &str = "https://api.mainnet-beta.solana.com";
