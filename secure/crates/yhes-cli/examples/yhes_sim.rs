//! DISPOSABLE SIMULATION ONLY. This Cargo example is never the shipping `yhes`.
//! Its software keys simulate two humans on one OS account; they provide no
//! Touch ID, Secure Enclave, Keychain protection, or isolation from that user.
mod sim_support;

use std::io::IsTerminal;

fn main() {
    eprintln!("yhes_sim: SIMULATION ONLY — disposable file keys; simulated consent; NO Touch ID");
    // This executable starts single-threaded. Discard credentials/overrides
    // before constructing any runtime, signer, Git channel or broker client.
    sim_support::clear_environment();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut input = std::io::stdin();
    let terminal = input.is_terminal();
    let outcome = sim_support::execute(&args, &mut input, terminal);
    println!("{}", outcome.stdout.trim_end());
    std::process::exit(outcome.exit);
}
