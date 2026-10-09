// standalone go-alpm read-path probe; replace points at the checked-out
// consumer so cgo links whichever libalpm.so.16 CGO_LDFLAGS/LD_LIBRARY_PATH
// select. built and run twice (puck vs real) by tests/consumers.sh.
module goalpm-probe

go 1.17

require github.com/Jguer/go-alpm/v2 v2.0.0

replace github.com/Jguer/go-alpm/v2 => ../../../consumers/go-alpm
