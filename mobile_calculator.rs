//! # Mobile Calculator Example
//! 
//! This example demonstrates basic FHE operations optimized for mobile understanding.
//! Perfect for beginners learning homomorphic encryption concepts.

use tfhe::prelude::*;
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Mobile Calculator with FHE");
    println!("===========================");
    
    // Step 1: Setup encryption configuration
    let config = ConfigBuilder::default().build();
    
    // Step 2: Generate keys (client & server)
    let (client_key, server_key) = generate_keys(config);
    println!("✅ Keys generated successfully!");
    
    // Step 3: Prepare some numbers to calculate
    let num1: u8 = 25;
    let num2: u8 = 15;
    
    println!("📊 Original numbers: {} and {}", num1, num2);
    
    // Step 4: Encrypt the numbers
    let encrypted_num1 = FheUint8::encrypt(num1, &client_key);
    let encrypted_num2 = FheUint8::encrypt(num2, &client_key);
    println!("🔒 Numbers encrypted!");
    
    // Step 5: Set server key for calculations
    set_server_key(server_key);
    
    // Step 6: Perform encrypted calculations
    println!("🧮 Performing encrypted calculations...");
    
    let encrypted_sum = &encrypted_num1 + &encrypted_num2;
    let encrypted_diff = &encrypted_num1 - &encrypted_num2;
    let encrypted_product = &encrypted_num1 * &encrypted_num2;
    
    // Step 7: Decrypt results
    let sum_result: u8 = encrypted_sum.decrypt(&client_key);
    let diff_result: u8 = encrypted_diff.decrypt(&client_key);
    let product_result: u8 = encrypted_product.decrypt(&client_key);
    
    // Step 8: Display results
    println!("\n📱 RESULTS:");
    println!("{} + {} = {}", num1, num2, sum_result);
    println!("{} - {} = {}", num1, num2, diff_result);
    println!("{} × {} = {}", num1, num2, product_result);
    
    // Verification
    assert_eq!(sum_result, num1 + num2);
    assert_eq!(diff_result, num1 - num2);
    assert_eq!(product_result, num1 * num2);
    
    println!("\n✅ All calculations verified!");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobile_calculator() {
        // This test ensures our example works correctly
        let result = main();
        assert!(result.is_ok());
    }
}
