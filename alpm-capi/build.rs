// the cdylib ships as libalpm.so.16: set the SONAME so consumers linking
// -lalpm record the versioned dependency the real libalpm has (readelf -d).
fn main() {
	println!("cargo::rustc-cdylib-link-arg=-Wl,-soname,libalpm.so.16");
}
