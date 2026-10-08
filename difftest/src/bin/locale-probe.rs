// run by difftest/tests/setlocale.rs, one process per environment
// (setlocale is process wide): glibc's setlocale(LC_ALL, "") against
// alpm_core::setlocale, then what pacman prints from it. compared: the
// outcome, the LC_TIME strings, decimal_point, CODESET, toupper and
// tolower of every byte; tm_zone, tm_isdst and tm_gmtoff of localtime;
// pacman's strftime(buf, 50, "%c") at the zone's offset changes, every
// weekday, month and half day, leap seconds, far years; random formats and buffer
// sizes against strftime. prints each difference and
// "compared <dates> formats <n> locale <ok>", exits 1 on any
use alpm_core::setlocale::{self, LC_CTYPE, LC_NUMERIC, LC_TIME, Locale};
use alpm_core::strftime::{Tm, strftime};
use alpm_core::tzfile;
use difftest::{
	Rng, c_langinfo, c_localtime_tm, c_setlocale_env, c_strftime_local,
	c_tolower, c_toupper, iters, zone_transitions,
};
use pacman_cli::package::format_date;

fn lossy(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

struct Diffs(Vec<String>);

impl Diffs {
	fn check(&mut self, what: &str, c: &[u8], r: &[u8]) {
		if c != r {
			self.0.push(format!(
				"DIFF {what} C={:?} rust={:?}",
				lossy(c),
				lossy(r)
			));
		}
	}
}

fn env(name: &str) -> Option<Vec<u8>> {
	std::env::var_os(name).map(|v| v.into_encoded_bytes())
}

// the LC_TIME string items: names, formats, era strings, alt months
fn time_items() -> impl Iterator<Item = usize> {
	(0..50).chain(110..123).chain(135..147)
}

fn compare_locale(d: &mut Diffs, l: &Locale) {
	for i in time_items() {
		let what = format!("LC_TIME item {i}");
		d.check(&what, &c_langinfo(LC_TIME, i), l.time.item(i));
	}
	d.check(
		"decimal_point",
		&c_langinfo(LC_NUMERIC, 0),
		&l.decimal_point,
	);
	d.check("codeset", &c_langinfo(LC_CTYPE, 14), &l.codeset);
	for c in 0..=255u8 {
		d.check(
			&format!("toupper {c}"),
			&[c_toupper(c)],
			&[l.toupper(c)],
		);
		d.check(
			&format!("tolower {c}"),
			&[c_tolower(c)],
			&[l.tolower(c)],
		);
	}
}

// the instants: offset changes and their neighbours, two weeks of every
// month of 2026 at four hours, far and random years
fn instants(rng: &mut Rng) -> Vec<i64> {
	let mut out = Vec::new();
	for t in zone_transitions() {
		out.extend([t - 1, t, t + 1]);
	}
	let jan1 = 1_767_225_600;
	for day in (0..365).step_by(5) {
		for h in [0, 11, 12, 23] {
			out.push(jan1 + day * 86_400 + h * 3600 + 1234);
		}
	}
	out.extend([
		0,
		-1,
		-62_167_219_200,
		-377_705_116_801,
		253_402_300_800,
		67_768_036_191_676_799,
		67_768_036_191_676_800,
		i64::MIN,
		i64::MAX,
	]);
	// the last leap second (right/ zones count them in time_t) and the
	// first, the seconds around
	for base in [1_483_228_826, 78_796_800] {
		out.extend(base - 40..base + 40);
	}
	for _ in 0..2000 {
		out.push((rng.next_u64() >> 20) as i64 - (1 << 43));
		out.push((rng.next_u64() >> 31) as i64 - (1 << 32));
	}
	out
}

// a random strftime format: text (UTF-8 too) and conversions with
// flags, widths and modifiers, sometimes a '%' at the end. no %s: the
// port's is t, glibc's mktime(localtime(t)) is not t around some
// historic transitions (Europe/Paris 1944) and no locale's %c uses it
fn format(rng: &mut Rng) -> Vec<u8> {
	const CONV: &[u8] =
		b"aAbBcCdDeFgGhHIjklmMnpPrRStTuUVwWxXyYzZ%+:qNfiJKLQv";
	let mut f = Vec::new();
	for _ in 0..1 + rng.below(4) {
		match rng.below(6) {
			0 => f.extend_from_slice(
				["x", " ", "é", "年"][rng.below(4)].as_bytes(),
			),
			_ => {
				f.push(b'%');
				for _ in 0..rng.below(3) {
					f.push(rng.pick(b"_-0^#"));
				}
				if rng.below(4) == 0 {
					f.extend(rng
						.below(40)
						.to_string()
						.bytes());
				}
				match rng.below(5) {
					0 => f.push(b'E'),
					1 => f.push(b'O'),
					_ => {}
				}
				f.push(rng.pick(CONV));
			}
		}
	}
	if rng.below(20) == 0 {
		f.push(b'%');
	}
	f
}

fn main() {
	setlocale::localize();
	let c_ok = c_setlocale_env();
	let port = Locale::from_env(&env);
	let mut d = Diffs(Vec::new());
	if c_ok != port.is_some() {
		d.0.push(format!(
			"DIFF setlocale C={c_ok} rust={}",
			port.is_some()
		));
	}
	let l = setlocale::current();
	if port.as_ref().is_some_and(|p| p != l) {
		d.0.push("DIFF current() is not from_env".into());
	}
	compare_locale(&mut d, l);
	let mut rng = Rng::new(0x10ca1e);
	let times = instants(&mut rng);
	for &t in &times {
		let c = c_localtime_tm(t);
		let r = tzfile::current().local(t);
		let show = |tm: &Option<Tm>| {
			tm.as_ref().map(|tm| {
				(tm.isdst != 0, lossy(&tm.zone), tm.gmtoff)
			})
		};
		let rshow =
			r.as_ref().map(|l| (l.isdst, lossy(&l.zone), l.gmtoff));
		if show(&c) != rshow {
			d.0.push(format!(
				"DIFF localtime t={t} C={:?} rust={rshow:?}",
				show(&c)
			));
		}
		let c = c_strftime_local(t, 50, b"%c").map(|(_, s)| s);
		d.check(
			&format!("date t={t}"),
			&c.unwrap_or_default(),
			&format_date(t).unwrap_or_default(),
		);
	}
	let n = iters() / 20;
	for _ in 0..n {
		let t = times[rng.below(times.len())];
		let fmt = format(&mut rng);
		let max = [1, 8, 20, 50, 256][rng.below(5)];
		let Some((cn, cs)) = c_strftime_local(t, max, &fmt) else {
			continue;
		};
		let tm = c_localtime_tm(t).unwrap();
		let r = strftime(max, &fmt, &tm, l);
		let ok = match &r {
			Some(s) if cn > 0 => *s == cs,
			Some(s) => s.is_empty(),
			None => cn == 0,
		};
		if !ok {
			d.0.push(format!(
				"DIFF strftime t={t} max={max} fmt={:?} C={cn} {:?} rust={:?}",
				lossy(&fmt),
				lossy(&cs),
				r.as_deref().map(lossy)
			));
		}
	}
	for line in d.0.iter().take(40) {
		println!("{line}");
	}
	println!("compared {} formats {n} locale {c_ok}", times.len());
	std::process::exit(i32::from(!d.0.is_empty()));
}
