// links the upstream C libalpm as reference, built by meson in pacman/build
//
// static libalpm_objlib.a (+ libcommon.a) instead of libalpm.so: hidden (internal) symbols
// stay linkable from an archive, so internal helpers can be compared too
use std::env;
use std::path::PathBuf;
use std::process::Command;

// same set as alpm_deps in pacman's meson.build
const DEPS: &[&str] =
	&["libarchive", "libcurl", "gpgme", "libcrypto", "libseccomp"];

fn main() {
	let dir = match env::var_os("PACMAN_BUILD") {
		Some(d) => PathBuf::from(d),
		None => {
			let root = env::var("CARGO_MANIFEST_DIR").unwrap();
			PathBuf::from(root).join("../pacman/build")
		}
	};
	// libalpm internals, and src/common shared by the pacman frontends
	for name in ["alpm_objlib", "common"] {
		let lib = dir.join(format!("lib{name}.a"));
		if !lib.exists() {
			panic!(
				"{} missing, build upstream first: \
				meson setup pacman/build pacman && ninja -C pacman/build",
				lib.display()
			);
		}
		println!("cargo:rerun-if-changed={}", lib.display());
	}
	let dir = dir.canonicalize().unwrap();

	// frontend objects
	//
	// src/pacman is built as loose objects (pacman.p/*.o), no archive.
	// pack copies into OUT_DIR, minus pacman.c.o: it only exports main,
	// which would clash with the test harness. the linker then pulls just
	// the members a wrapper references (util.o, plus conf.o for config
	// and callback.o for multibar_move_completed_up). emitted before
	// libalpm/libcommon so those resolve the frontend's references.
	let objs: Vec<PathBuf> = std::fs::read_dir(dir.join("pacman.p"))
		.expect("pacman.p missing, build upstream first")
		.map(|e| e.unwrap().path())
		.filter(|p| p.extension().is_some_and(|x| x == "o"))
		.filter(|p| !p.ends_with("src_pacman_pacman.c.o"))
		.collect();
	let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
	let lib = out_dir.join("libpacman_frontend.a");
	// ar appends to an existing archive, start fresh
	if lib.exists() {
		std::fs::remove_file(&lib).unwrap();
	}
	let st = Command::new("ar")
		.arg("crs")
		.arg(&lib)
		.args(&objs)
		.status()
		.expect("ar not found");
	if !st.success() {
		panic!("ar failed: {st}");
	}
	for o in &objs {
		println!("cargo:rerun-if-changed={}", o.display());
	}
	println!("cargo:rustc-link-search=native={}", out_dir.display());
	println!("cargo:rustc-link-lib=static:-bundle=pacman_frontend");
	// end frontend objects

	println!("cargo:rerun-if-env-changed=PACMAN_BUILD");
	println!("cargo:rustc-link-search=native={}", dir.display());
	// thin archives, rustc must not try to bundle them into the rlib
	println!("cargo:rustc-link-lib=static:-bundle=alpm_objlib");
	println!("cargo:rustc-link-lib=static:-bundle=common");

	let out = Command::new("pkg-config")
		.arg("--libs")
		.args(DEPS)
		.output()
		.expect("pkg-config not found");
	if !out.status.success() {
		panic!("pkg-config: {}", String::from_utf8_lossy(&out.stderr));
	}
	for flag in String::from_utf8(out.stdout).unwrap().split_whitespace() {
		if let Some(name) = flag.strip_prefix("-l") {
			println!("cargo:rustc-link-lib=dylib={name}");
		} else if let Some(path) = flag.strip_prefix("-L") {
			println!("cargo:rustc-link-search=native={path}");
		}
	}
}
