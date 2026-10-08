// the sandbox download helper, entered the way pacman's main will: the
// tests point HelperSandbox::program here instead of /proc/self/exe
fn main() {
	if let Some(code) = alpm_core::sandbox::helper_entry() {
		std::process::exit(code);
	}
	eprintln!("usage: sandbox-helper {}", alpm_core::sandbox::HELPER_ARG);
	std::process::exit(2);
}
