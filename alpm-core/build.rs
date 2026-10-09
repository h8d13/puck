// SCRIPTLET_SHELL and LDCONFIG of config.h (meson options scriptlet-shell
// and ldconfig), as PUCK_SCRIPTLET_SHELL and PUCK_LDCONFIG for util.rs.
//
// one source for both sides: with PACMAN_BUILD set the values come from
// that build's config.h, so difftest compares the port with the C it was
// configured next to, and the PKGBUILD passes Arch's paths to meson once
// and builds the port against that build. meson's defaults otherwise
// (a plain cargo build without a C reference)
use std::env;
use std::fs;
use std::path::PathBuf;

const OPTIONS: [(&str, &str); 2] = [
	("SCRIPTLET_SHELL", "/bin/sh"),
	("LDCONFIG", "/sbin/ldconfig"),
];

fn main() {
	println!("cargo:rerun-if-env-changed=PACMAN_BUILD");
	let config = match env::var_os("PACMAN_BUILD") {
		Some(d) => {
			let path = PathBuf::from(d).join("config.h");
			println!("cargo:rerun-if-changed={}", path.display());
			let missing = format!(
				"{}: run meson setup first",
				path.display()
			);
			fs::read_to_string(&path).expect(&missing)
		}
		None => String::new(),
	};
	for (name, default) in OPTIONS {
		let value = define(&config, name)
			.unwrap_or_else(|| default.to_string());
		println!("cargo:rustc-env=PUCK_{name}={value}");
	}
}

// the string of `#define <name> "<value>"`, meson's set_quoted escaping
// ('\\' and '\"') undone
fn define(config: &str, name: &str) -> Option<String> {
	let prefix = format!("#define {name} \"");
	let quoted = config
		.lines()
		.find_map(|l| l.strip_prefix(&prefix))?
		.strip_suffix('"')?;
	let mut value = String::new();
	let mut chars = quoted.chars();
	while let Some(c) = chars.next() {
		value.push(if c == '\\' { chars.next()? } else { c });
	}
	Some(value)
}
