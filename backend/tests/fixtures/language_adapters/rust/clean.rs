// TEST DATA FIXTURE - CLEAN SAFE RUST
pub fn safe_convert(val: u64) -> [u8; 8] {
    // Safe standard library integer conversions
    val.to_ne_bytes()
}

pub fn calculate_sum(nums: &[i32]) -> i32 {
    nums.iter().sum()
}
