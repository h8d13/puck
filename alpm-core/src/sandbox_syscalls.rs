// port of lib/libalpm/sandbox_syscalls.c through the libseccomp crate,
// the same C library pacman links
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
use rustix::io::Errno;

use crate::callbacks::{Callbacks, LogLevel};

// denied_syscalls, in the C's order. chroot and pivot_root are listed
// twice there too: duplicate rules succeed, so both count in the log
pub const DENIED_SYSCALLS: &[&str] = &[
	// kernel modules
	"delete_module",
	"finit_module",
	"init_module",
	// mount
	"chroot",
	"fsconfig",
	"fsmount",
	"fsopen",
	"fspick",
	"mount",
	"mount_setattr",
	"move_mount",
	"open_tree",
	"pivot_root",
	"umount",
	"umount2",
	// keyring
	"add_key",
	"keyctl",
	"request_key",
	// CPU emulation
	"modify_ldt",
	"subpage_prot",
	"switch_endian",
	"vm86",
	"vm86old",
	// debug
	"kcmp",
	"lookup_dcookie",
	"perf_event_open",
	"pidfd_getfd",
	"ptrace",
	"rtas",
	"sys_debug_setcontext",
	// set clock
	"adjtimex",
	"clock_adjtime",
	"clock_adjtime64",
	"clock_settime",
	"clock_settime64",
	"settimeofday",
	// raw IO
	"ioperm",
	"iopl",
	"pciconfig_iobase",
	"pciconfig_read",
	"pciconfig_write",
	// kexec
	"kexec_file_load",
	"kexec_load",
	// reboot
	"reboot",
	// privileged
	"acct",
	"bpf",
	"capset",
	"chroot",
	"fanotify_init",
	"fanotify_mark",
	"nfsservctl",
	"open_by_handle_at",
	"pivot_root",
	"personality",
	// obsolete
	"_sysctl",
	"afs_syscall",
	"bdflush",
	"break",
	"create_module",
	"ftime",
	"get_kernel_syms",
	"getpmsg",
	"gtty",
	"idle",
	"lock",
	"mpx",
	"prof",
	"profil",
	"putpmsg",
	"query_module",
	"security",
	"sgetmask",
	"ssetmask",
	"stime",
	"stty",
	"sysfs",
	"tuxcall",
	"ulimit",
	"uselib",
	"ustat",
	"vserver",
	// swap
	"swapon",
	"swapoff",
];

// _alpm_sandbox_syscalls_filter: every listed syscall fails with EPERM,
// the rest is allowed. names the native arch lacks are skipped, a rule
// that cannot be added is logged and skipped
pub fn syscalls_filter(cb: &mut dyn Callbacks) -> bool {
	let Ok(mut ctx) = ScmpFilterContext::new(ScmpAction::Allow) else {
		cb.log(
			LogLevel::Error,
			b"error initializing seccomp to filter system calls \
			in the download sandbox!\n",
		);
		return false;
	};
	// the C prints errno after seccomp_load: the kernel's error, which
	// libseccomp's return value reports only with this set
	let _ = ctx.set_api_sysrawrc(true);
	let eperm = ScmpAction::Errno(Errno::PERM.raw_os_error());
	let mut restricted = 0;
	for name in DENIED_SYSCALLS {
		let Ok(syscall) = ScmpSyscall::from_name(name) else {
			continue;
		};
		if ctx.add_rule(eperm, syscall).is_err() {
			let m = format!(
				"error restricting syscall {name} via seccomp!\n"
			);
			cb.log(LogLevel::Error, m.as_bytes());
		} else {
			restricted += 1;
		}
	}
	match ctx.load() {
		Err(e) => {
			let errno = e.sysrawrc().map_or(0, |rc| -rc);
			let m = format!(
				"error restricting syscalls via seccomp: {errno}!\n"
			);
			cb.log(LogLevel::Error, m.as_bytes());
			false
		}
		Ok(()) => {
			let m = format!(
				"successfully restricted {restricted} syscalls \
				via seccomp\n"
			);
			cb.log(LogLevel::Debug, m.as_bytes());
			true
		}
	}
}
