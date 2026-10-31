// TEST DATA FIXTURE - RUST CODE PATTERNS FOR AUDITING
use std::mem;

pub fn inspect_memory(val: u64) -> [u8; 8] {
    // Unsafe block for auditing (ENT-RUST-001)
    unsafe {
        // High-risk transmutation (ENT-RUST-002)
        let bytes: [u8; 8] = mem::transmute(val);

        // Raw pointer dereference (ENT-RUST-003)
        let raw_ptr: *const u8 = bytes.as_ptr();
        let first_byte = *raw_ptr;
        println!("First byte: {}", first_byte);

        bytes
    }
}
