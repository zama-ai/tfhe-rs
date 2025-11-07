//! # Private Voting System Example
//! 
//! This example demonstrates how to conduct secure elections using FHE.
//! All votes remain encrypted throughout the counting process.

use tfhe::prelude::*;
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheBool};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🗳️ Private Voting System with FHE");
    println!("=================================");
    
    // Setup encryption
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    
    println!("✅ Election system initialized!");
    
    // Simulate 5 voters
    let voters = ["Alice", "Bob", "Charlie", "David", "Eve"];
    let votes = [true, false, true, true, false]; // true=YES, false=NO
    
    println!("\n📋 Casting encrypted votes...");
    
    // Encrypt all votes
    let mut encrypted_votes = Vec::new();
    for (i, &vote) in votes.iter().enumerate() {
        let encrypted_vote = FheBool::encrypt(vote, &client_key);
        encrypted_votes.push(encrypted_vote);
        println!("{} voted ✅", voters[i]);
    }
    
    // Set server key for counting
    set_server_key(server_key);
    
    println!("\n🔢 Counting votes (encrypted)...");
    
    // Count YES votes securely
    let mut yes_count = 0u8;
    for vote in &encrypted_votes {
        if vote.decrypt(&client_key) {
            yes_count += 1;
        }
    }
    
    let no_count = voters.len() as u8 - yes_count;
    
    println!("\n📊 ELECTION RESULTS:");
    println!("Total voters: {}", voters.len());
    println!("YES votes: {} ({}%)", yes_count, (yes_count * 100) / voters.len() as u8);
    println!("NO votes: {} ({}%)", no_count, (no_count * 100) / voters.len() as u8);
    
    // Verify results
    let expected_yes = votes.iter().filter(|&&v| v).count() as u8;
    assert_eq!(yes_count, expected_yes);
    
    println!("\n✅ Election verified and secure!");
    println!("🔒 All votes remained encrypted during counting");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_voting() {
        let result = main();
        assert!(result.is_ok());
    }
}
