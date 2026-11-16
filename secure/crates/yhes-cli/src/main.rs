//! Production entry point. The signer is the authenticated native app and
//! vault keys come from the platform keychain. Nothing here can be switched.
use std::io::IsTerminal;
use yhes_cli::{native::NativeSigner, run, Deps, Failure, PlatformCustody, SystemClock};

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut stderr = std::io::stderr();
    let private_root = match yhes_cli::profile::application_support() {
        Ok(path) => path.join("engine"),
        Err(failure) => fail(&failure),
    };
    let signer = NativeSigner::production();
    let mut deps = Deps {
        signer: &signer,
        custody: &PlatformCustody,
        clock: &SystemClock,
        private_root,
        progress: &mut stderr,
    };
    let mut stdin = std::io::stdin();
    let terminal = stdin.is_terminal();
    let outcome = run(&argv, &mut stdin, terminal, &mut deps);
    print!("{}", outcome.stdout);
    std::process::exit(outcome.exit);
}

fn fail(failure: &Failure) -> ! {
    println!(
        "{}",
        serde_json::json!({"ok": false, "error": failure.to_json()})
    );
    std::process::exit(1);
}
