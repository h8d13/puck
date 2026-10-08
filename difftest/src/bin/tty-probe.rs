// run by difftest/tests/cli_util2.rs on a pty: getcols on a terminal
// stdout, the yesno prompt's flush_term_input on a terminal stdin, C or
// Rust side; the result goes to stderr as "result <value>"
use pacman_cli::conf::Config;
use pacman_cli::pacman::{std_sink, std_term};
use pacman_cli::util::{Output, getcols, yesno};

fn main() {
	let mode = std::env::args().nth(1).unwrap_or_default();
	let result = match mode.as_str() {
		"cols" => {
			let (c, r) = difftest::getcols_both(None, getcols);
			format!("{c} {r}")
		}
		"yesno-c" => difftest::c_tty_yesno(b"go?").to_string(),
		"yesno-rust" => {
			let mut out = Output {
				sink: Some(std_sink),
				..Output::default()
			};
			let mut term = std_term();
			let cfg = Config::new();
			let r = yesno(&mut out, &cfg, &mut term, b"go?");
			out.flush();
			i32::from(r).to_string()
		}
		_ => {
			eprintln!("usage: tty-probe cols|yesno-c|yesno-rust");
			std::process::exit(2);
		}
	};
	eprintln!("result {result}");
}
