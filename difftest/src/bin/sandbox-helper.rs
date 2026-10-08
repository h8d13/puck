// the sandbox download helper, entered the way pacman's main will: the
// tests point HelperSandbox::program here instead of /proc/self/exe.
// a watchdog ends a helper still running after 60 s (exit 124, like
// timeout(1)); an exec'd command replaces it and brings its own
fn main() {
	std::thread::spawn(|| {
		std::thread::sleep(std::time::Duration::from_secs(60));
		std::process::exit(124);
	});
	if let Some(code) = alpm_core::sandbox::helper_entry() {
		std::process::exit(code);
	}
	eprintln!("usage: sandbox-helper {}", alpm_core::sandbox::HELPER_ARG);
	std::process::exit(2);
}
