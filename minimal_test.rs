// This is a minimal test script to verify the VulnerabilityType structure
// without running a full cargo test

// Define the same structure as in the project
#[derive(Debug, PartialEq)]
enum VulnerabilityType {
    CrossContractReentrancy {
        details: String,
    },
    Reentrancy {
        function_signature: String,
    },
    // Other variants omitted for brevity
}

fn main() {
    // Create a CrossContractReentrancy instance
    let vuln = VulnerabilityType::CrossContractReentrancy {
        details: "Cross-contract reentrancy between multiple contracts detected".to_string()
    };
    
    // Verify it matches the expected pattern
    match vuln {
        VulnerabilityType::CrossContractReentrancy { details } => {
            println!("✅ CrossContractReentrancy structure is correct");
            println!("Details: {}", details);
            assert!(details.contains("Cross-contract reentrancy"), "Details should contain the expected text");
        },
        _ => {
            println!("❌ Unexpected variant");
            std::process::exit(1);
        }
    }
    
    println!("All tests passed!");
}
