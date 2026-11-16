//! Binds the signer's Apple team into the artifact at build time. A build
//! without `YHES_SIGNING_TEAM` has no trusted signer and fails closed at run time.
fn main() {
    println!("cargo:rerun-if-env-changed=YHES_SIGNING_TEAM");
    if let Ok(team) = std::env::var("YHES_SIGNING_TEAM") {
        let valid = team.len() == 10
            && team
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
        if !valid {
            panic!("YHES_SIGNING_TEAM must be a 10-character Apple team identifier");
        }
        println!("cargo:rustc-env=YHES_PINNED_SIGNER_TEAM={team}");
    }
}
