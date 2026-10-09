# sourced by bench/t/bNNNN-*.sh, the bench analog of git's t/test-lib.sh:
# each script declares ops with bench_op and ends with bench_done; this
# file parses the options, sets up a trash dir, runs every op on C pacman
# and puck in the chosen mode and prints TAP (prove bench/t/b*.sh works)
#
# usage: bench/t/bNNNN-name.sh [options]
#   -n N, --runs=N     timed runs per side (time mode, perf stat), default 7
#   --run=1-3,5        only these ops (by number)
#   --side=c|puck|both default both for time, puck for the profiling
#                      modes (--side=c profiles the C reference instead)
#   --top=N            hotspots listed under each op in profiling modes,
#                      default 5, 0 for none
#   -v, --verbose      commands and per-run numbers on stderr
#   -i, --immediate    stop at the first failing op
#   -d, --debug        keep the trash dir (bench/trash.<script>)
#   -c PATH, -p PATH   C pacman (BENCH_C, /usr/bin/pacman), puck
#                      (BENCH_PUCK, target/release/puck)
#   modes, one per invocation. time compares C and puck; the others
#   profile one binary, puck unless --side says otherwise:
#   (default)          median wall time and peak RSS, alternating sides
#   --valgrind[=TOOL]  memcheck (default), massif, dhat, callgrind,
#                      cachegrind; one run per side
#   --perf[=stat]      perf stat counters over -n runs
#   --perf=record      perf record, report saved next to perf.data
#   --strace           strace -f -c syscall counts
#
# per op, results/<script>/<N>/<side>.{out,err,...} keep each side's
# output and the tool's files (massif.out, callgrind.out, perf.data, ...)
# from the last run; results/<script>.tsv has one line per op and side.
# in time mode an op is "not ok" when the sides' rc, stdout or stderr
# differ, and bench_expect_diff marks a known difference, like git's
# test_expect_failure; in profiling modes it is "not ok" when memcheck
# finds errors or definite leaks
#
# script API:
#   bench_op [PREREQ] ARG...         pacman ARG... on both sides
#   bench_expect_diff [PREREQ] ARG...  same, output known to differ
#   bench_lazy_prereq NAME 'SCRIPT'  NAME holds if SCRIPT succeeds (run
#                                    once, in the trash dir)
#   bench_reset SIDE                 redefine: called untimed before
#                                    every run, in the trash dir, to
#                                    restore state an op changes
#   bench_done

set -u

bench_name=$(basename "$0" .sh)
BENCH_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$BENCH_DIR/.." && pwd)

runs=${BENCH_RUNS:-7}
mode='time'
tool=
sides=''
top=5
verbose=
immediate=
keep=
run_list=
BENCH_C=${BENCH_C:-/usr/bin/pacman}
BENCH_PUCK=${BENCH_PUCK:-$REPO/target/release/puck}

bail () {
	echo "Bail out! $*"
	exit 1
}

while [ $# -gt 0 ]; do
	case $1 in
	-n) runs=${2?-n needs a count}; shift ;;
	--runs=*) runs=${1#*=} ;;
	--run=*) run_list=${1#*=} ;;
	--side=both) sides="c puck" ;;
	--side=c|--side=puck) sides=${1#*=} ;;
	--top=*) top=${1#*=} ;;
	-v|--verbose) verbose=t ;;
	-i|--immediate) immediate=t ;;
	-d|--debug) keep=t ;;
	-c) BENCH_C=${2?-c needs a path}; shift ;;
	-p) BENCH_PUCK=${2?-p needs a path}; shift ;;
	--valgrind) mode=valgrind tool=memcheck ;;
	--valgrind=*) mode=valgrind tool=${1#*=} ;;
	--perf) mode=perf tool=stat ;;
	--perf=*) mode=perf tool=${1#*=} ;;
	--strace) mode=strace tool=strace ;;
	-h|--help) sed -n '/^# usage/,/^$/s/^# \{0,1\}//p' "$BENCH_DIR/bench-lib.sh"
		exit 0 ;;
	*) bail "unknown option $1" ;;
	esac
	shift
done

case $mode/$tool in
time/|strace/strace|perf/stat|perf/record) ;;
valgrind/memcheck|valgrind/massif|valgrind/dhat) ;;
valgrind/callgrind|valgrind/cachegrind) ;;
*) bail "unknown $mode tool '$tool'" ;;
esac
case $mode in
time) command -v /usr/bin/time >/dev/null || bail "needs GNU time" ;;
*) command -v "$mode" >/dev/null || bail "needs $mode" ;;
esac
case $runs in ''|*[!0-9]*|0) bail "bad run count '$runs'" ;; esac
case $top in ''|*[!0-9]*) bail "bad --top '$top'" ;; esac
if [ -z "$sides" ]; then
	if [ "$mode" = time ]; then sides="c puck"; else sides=puck; fi
fi

BENCH_C=$(realpath -e "$BENCH_C" 2>/dev/null) || bail "no C pacman"
BENCH_PUCK=$(realpath -e "$BENCH_PUCK" 2>/dev/null) ||
	bail "no puck (cargo build --release -p pacman-cli)"
[ -x "$BENCH_C" ] && [ -x "$BENCH_PUCK" ] || bail "binaries not executable"

# deterministic output on both sides, like git's pinned test env
export LC_ALL=C.UTF-8 COLUMNS=80 TZ=UTC

# each side runs as "pacman" found through its own PATH dir, so argv[0]
# matches and every wrapper (time, valgrind, perf, strace) just execs a
# plain command: no bash -c exec -a shim inflating peak RSS
TRASH=$BENCH_DIR/trash.$bench_name
RESULTS=$BENCH_DIR/results/$bench_name
rm -rf "$TRASH" "$RESULTS"
mkdir -p "$TRASH/.bin/c" "$TRASH/.bin/puck" "$TRASH/.bin/true" "$RESULTS"
ln -s "$BENCH_C" "$TRASH/.bin/c/pacman"
ln -s "$BENCH_PUCK" "$TRASH/.bin/puck/pacman"
ln -s "$(type -P true)" "$TRASH/.bin/true/pacman"
printf '# op\tside\tmode\tvalue\tsummary\n' >"$RESULTS.tsv"

bench_cleanup () {
	if [ -n "$keep" ]; then
		echo "# kept $TRASH" >&2
	else
		rm -rf "$TRASH"
	fi
}
trap bench_cleanup EXIT

say () {
	[ -z "$verbose" ] || echo "# $*" >&2
}

bench_reset () {
	:
}

# bench_exec SIDE BASE CMD...: CMD in the trash dir with "pacman"
# resolving to SIDE's binary; stdout/stderr to BASE.out/.err, rc in
# bench_rc
bench_exec () {
	local side=$1 base=$2
	shift 2
	say "$side: $*"
	(
		cd "$TRASH" &&
		export PATH=$TRASH/.bin/$side:$PATH &&
		exec "$@"
	) >"$base.out" 2>"$base.err"
	bench_rc=$?
}

# numbers: bash only has integers, so values stay in us, KiB, bytes and
# counts, and are printed with a fixed decimal

fmt_us () {
	if [ "$1" -lt 10000000 ]; then
		printf '%d.%d ms' $(($1 / 1000)) $(($1 / 100 % 10))
	else
		printf '%d.%02d s' $(($1 / 1000000)) $(($1 / 10000 % 100))
	fi
}

fmt_kib () {
	printf '%d.%d MB' $(($1 / 1024)) $(($1 * 10 / 1024 % 10))
}

fmt_count () {
	if [ "$1" -ge 1000000000 ]; then
		printf '%d.%02dG' $(($1 / 1000000000)) $(($1 / 10000000 % 100))
	elif [ "$1" -ge 1000000 ]; then
		printf '%d.%02dM' $(($1 / 1000000)) $(($1 / 10000 % 100))
	elif [ "$1" -ge 1000 ]; then
		printf '%d.%dk' $(($1 / 1000)) $(($1 / 100 % 10))
	else
		printf '%d' "$1"
	fi
}

# puck / C as "0.52x"
ratio () {
	if [ -z "${1:-}" ] || [ -z "${2:-}" ] || [ "$1" -eq 0 ]; then
		printf '%5s' -
		return
	fi
	local r=$(($2 * 100 / $1))
	printf '%2d.%02dx' $((r / 100)) $((r % 100))
}

median () {
	printf '%s\n' "$@" | sort -n | sed -n "$((($# + 1) / 2))p"
}

# valgrind and perf print counts with thousands separators
digits () {
	local v=${1//,/}
	printf '%s' "${v:-0}"
}

# vg_num LOG PATTERN: the number PATTERN's \( \) group catches, from
# the main process's lines only. C pacman forks children that never exec
# (7 on -Q), and valgrind logs each one's summary into the same file
vg_num () {
	local pid
	pid=$(sed -n '1s/^==\([0-9]*\)==.*/\1/p' "$1")
	digits "$(sed -n "s/^==$pid==.*$2.*/\\1/p" "$1" | head -n 1)"
}

# one /usr/bin/time run: wall in us (minus the harness overhead, see
# calibrate) and peak RSS in KiB of the pacman process alone
time_run () {
	local side=$1 base=$2 t0 t1
	shift 2
	t0=${EPOCHREALTIME//[.,]/}
	bench_exec "$side" "$base" /usr/bin/time -f %M -o "$base.time" \
		pacman "$@"
	t1=${EPOCHREALTIME//[.,]/}
	wall=$((t1 - t0 - overhead))
	[ "$wall" -ge 0 ] || wall=0
	# time puts "Command exited with non-zero status" above the format
	rss=$(tail -n 1 "$base.time")
	say "$side: $(fmt_us "$wall") $(fmt_kib "$rss") rc $bench_rc"
}

# the subshell, fork and two execs around each run cost about the same
# on both sides; measured once on /usr/bin/true and subtracted, so the
# ratios compare the binaries and not the harness
calibrate () {
	local i t=()
	overhead=0
	for i in 1 2 3 4 5 6 7 8 9 10 11; do
		time_run true "$TRASH/calibrate"
		t+=("$wall")
	done
	overhead=$(median "${t[@]}")
	rm -f "$TRASH"/calibrate.*
}

# compare the last run's rc and output on both sides: same, DIFF or -
compare_sides () {
	local dir=$1
	if [ "$sides" != "c puck" ]; then
		echo -
	elif [ "${rc[c]}" = "${rc[puck]}" ] &&
		cmp -s "$dir/c.out" "$dir/puck.out" &&
		cmp -s "$dir/c.err" "$dir/puck.err"; then
		echo same
	else
		echo DIFF
	fi
}

# modes: each fills txt[side] (shown), num[side] (the headline number,
# stored in the tsv) and bad (non-empty fails the op); time also sets rat
# (puck/C) and out (same/DIFF/-), the profiling modes write hotspots to
# BASE.top, listed under the op

# top_annotate [STRIP]: the first $top functions of a callgrind_annotate
# or cg_annotate listing on stdin as "  12.34%  function  (object)".
# callgrind writes "file:function [object]" (STRIP drops "file:"),
# cg_annotate groups functions under "< ... file:" lines, so both are
# ranked by count again
top_annotate () {
	local count pct fn obj
	while read -r count pct fn obj; do
		case $count in [0-9]*) ;; *) continue ;; esac
		case $pct in "("*) ;; *) continue ;; esac
		# "(" and " 7.49%)" split on the inner blank
		[ "$pct" != "(" ] || read -r pct fn obj <<<"$fn $obj"
		pct=${pct#(} pct=${pct%)} pct=${pct%%,*}
		case $fn in PROGRAM|unannotated:) continue ;; esac
		[ -z "${1:-}" ] || fn=${fn#*:}
		obj=${obj#[} obj=${obj%]}
		printf '%s\t%7s  %s%s\n' "${count//,/}" "$pct" "$fn" \
			"${obj:+  (${obj##*/})}"
	done | sort -rn | head -n "$top" | cut -f 2-
}


op_time () {
	local dir=$1 side i
	shift
	local -a c_t=() c_m=() puck_t=() puck_m=()
	out=same
	for side in $sides; do
		bench_reset "$side"
		time_run "$side" "$dir/$side" "$@"
	done
	for ((i = 0; i < runs; i++)); do
		for side in $sides; do
			bench_reset "$side"
			time_run "$side" "$dir/$side" "$@"
			rc[$side]=$bench_rc
			if [ "$side" = c ]; then
				c_t+=("$wall") c_m+=("$rss")
			else
				puck_t+=("$wall") puck_m+=("$rss")
			fi
		done
		[ "$(compare_sides "$dir")" != DIFF ] || out=DIFF
	done
	[ "$sides" = "c puck" ] || out=-
	local ct cm pt pm
	[ ${#c_t[@]} -eq 0 ] || {
		ct=$(median "${c_t[@]}") cm=$(median "${c_m[@]}")
		txt[c]=$(printf '%10s %8s' "$(fmt_us "$ct")" "$(fmt_kib "$cm")") num[c]=$ct
	}
	[ ${#puck_t[@]} -eq 0 ] || {
		pt=$(median "${puck_t[@]}") pm=$(median "${puck_m[@]}")
		txt[puck]=$(printf '%10s %8s' "$(fmt_us "$pt")" "$(fmt_kib "$pm")") num[puck]=$pt
	}
	rat="$(ratio "${ct:-}" "${pt:-}") $(ratio "${cm:-}" "${pm:-}")"
}

op_valgrind () {
	local dir=$1 side b v e l
	shift
	for side in $sides; do
		b=$dir/$side
		local -a vg=(--tool="$tool" --log-file="$b.vg")
		case $tool in
		memcheck) vg+=(--leak-check=full --errors-for-leak-kinds=definite) ;;
		massif) vg+=(--massif-out-file="$b.massif") ;;
		dhat) vg+=(--dhat-out-file="$b.dhat") ;;
		callgrind) vg+=(--callgrind-out-file="$b.callgrind") ;;
		cachegrind) vg+=(--cachegrind-out-file="$b.cachegrind") ;;
		esac
		bench_reset "$side"
		bench_exec "$side" "$b" valgrind "${vg[@]}" pacman "$@"
		rc[$side]=$bench_rc
		case $tool in
		memcheck)
			e=$(vg_num "$b.vg" 'ERROR SUMMARY: \([0-9,]*\) errors')
			l=$(vg_num "$b.vg" 'definitely lost: \([0-9,]*\) bytes')
			txt[$side]="$e errors, $l B lost" num[$side]=$e
			if [ "$e" -ne 0 ] || [ "$l" -ne 0 ]; then
				bad=memcheck
			fi
			# the error kinds, most frequent first
			sed -n 's/^==[0-9]*== \(Invalid .*\|Conditional .*\|Use of uninit.*\|Mismatched .*\|.* definitely lost in .*\)/\1/p' \
				"$b.vg" | sed 's/ in loss record.*//' | sort | uniq -c |
				sort -rn | head -n "$top" >"$b.top"
			;;
		massif)
			# peak of heap plus allocator overhead over all snapshots
			local k h=0 peak=0
			while IFS='=' read -r k v; do
				case $k in
				mem_heap_B) h=$v ;;
				mem_heap_extra_B) [ $((h + v)) -le "$peak" ] ||
					peak=$((h + v)) ;;
				esac
			done <"$b.massif"
			txt[$side]="peak heap $(fmt_kib $((peak / 1024)))"
			num[$side]=$peak
			echo "ms_print $b.massif" >"$b.top"
			;;
		dhat)
			v=$(vg_num "$b.vg" 'Total: *\([0-9,]*\) bytes')
			e=$(vg_num "$b.vg" 'At t-gmax: *\([0-9,]*\) bytes')
			txt[$side]="$(fmt_count "$v")B total, $(fmt_count "$e")B max"
			num[$side]=$v
			# per call site: valgrind's dh_view.html reads the json
			echo "dh_view.html: $b.dhat" >"$b.top"
			;;
		callgrind)
			v=$(vg_num "$b.vg" 'Collected : *\([0-9,]*\)')
			txt[$side]="$(fmt_count "$v") Ir" num[$side]=$v
			callgrind_annotate "$b.callgrind" 2>/dev/null |
				top_annotate strip >"$b.top"
			;;
		cachegrind)
			v=$(vg_num "$b.vg" 'I *refs: *\([0-9,]*\)')
			txt[$side]="$(fmt_count "$v") Ir" num[$side]=$v
			cg_annotate "$b.cachegrind" 2>/dev/null |
				top_annotate >"$b.top"
			;;
		esac
	done
}

op_perf () {
	local dir=$1 side b
	shift
	for side in $sides; do
		b=$dir/$side
		bench_reset "$side"
		if [ "$tool" = stat ]; then
			# :u, user space only: what perf_event_paranoid 2 allows
			bench_exec "$side" "$b" perf stat -x , -r "$runs" \
				-o "$b.perf" \
				-e task-clock,instructions:u,cycles:u,branch-misses:u \
				pacman "$@"
			rc[$side]=$bench_rc
			# hybrid cpus count per core type (cpu_core/instructions/u,
			# cpu_atom/...): summed
			local val ev ms=n/a ins=0
			while IFS=, read -r val _ ev _; do
				case $ev in
				task-clock*) ms=${val%.*}.${val#*.} ;;
				*instructions*) case $val in [0-9]*) ins=$((ins + ${val%%.*})) ;; esac ;;
				esac
			done <"$b.perf"
			txt[$side]="${ms} ms $(fmt_count "${ins:-0}") ins"
			num[$side]=$ins
		else
			bench_exec "$side" "$b" perf record -q --all-user \
				--call-graph dwarf -o "$b.perf.data" pacman "$@"
			rc[$side]=$bench_rc
			perf report -i "$b.perf.data" --stdio --no-children -q \
				-g none --sort dso,symbol 2>/dev/null >"$b.report"
			# "  12.34%  dso  [.] symbol  -  -"; symbols hold spaces
			local pct sym
			read -r pct _ _ sym < <(grep -m 1 '%' "$b.report")
			sym=${sym%%  *}
			local p d f
			while read -r p d _ f; do
				printf '%7s  %s  (%s)\n' "$p" "${f%%  *}" "$d"
			done < <(grep '%' "$b.report" | head -n "$top") >"$b.top"
			txt[$side]="top ${pct:-?} ${sym:0:40}" num[$side]=
		fi
	done
}

op_strace () {
	local dir=$1 side b l calls
	shift
	for side in $sides; do
		b=$dir/$side
		bench_reset "$side"
		bench_exec "$side" "$b" strace -f -c -S calls -o "$b.strace" \
			pacman "$@"
		rc[$side]=$bench_rc
		# "% time seconds usecs/call calls [errors] syscall": calls is
		# the 4th field whether errors is empty or not
		calls=0
		: >"$b.top"
		while read -r -a l; do
			case ${l[0]:-} in
			[0-9]*)
				if [ "${l[-1]}" = total ]; then
					calls=${l[3]}
				elif [ "$(wc -l <"$b.top")" -lt "$top" ]; then
					printf '%7s  %s\n' "${l[3]}" "${l[-1]}" >>"$b.top"
				fi ;;
			esac
		done <"$b.strace"
		txt[$side]="$calls syscalls" num[$side]=$calls
	done
	out=$(compare_sides "$dir")
	rat=$(ratio "${num[c]:-}" "${num[puck]:-}")
}

# prereqs, like git's test_lazy_prereq

declare -A prereq_script prereq_have
bench_lazy_prereq () {
	prereq_script[$1]=$2
}

bench_have_prereq () {
	local p
	for p in ${1//,/ }; do
		if [ -z "${prereq_have[$p]:-}" ]; then
			[ -n "${prereq_script[$p]:-}" ] || bail "unknown prereq $p"
			if (cd "$TRASH" && eval "${prereq_script[$p]}") \
				>/dev/null 2>&1; then
				prereq_have[$p]=yes
			else
				prereq_have[$p]=no
			fi
		fi
		[ "${prereq_have[$p]}" = yes ] || { missing=$p; return 1; }
	done
}

selected () {
	local r
	[ -n "$run_list" ] || return 0
	for r in ${run_list//,/ }; do
		case $r in
		*-*) [ "$1" -ge "${r%-*}" ] && [ "$1" -le "${r#*-}" ] && return 0 ;;
		*) [ "$1" -eq "$r" ] && return 0 ;;
		esac
	done
	return 1
}

bench_count=0 bench_ok=0 bench_fail=0 bench_known=0 bench_fixed=0
bench_skip=0

bench_run_ () {
	local expect=$1 prereq='' label status note='' side cells=''
	shift
	case ${1:-} in
	[A-Z]*) prereq=$1; shift ;;
	esac
	label=$*
	bench_count=$((bench_count + 1))
	if ! selected "$bench_count"; then
		bench_skip=$((bench_skip + 1))
		echo "ok $bench_count - $label # SKIP --run"
		return
	fi
	local missing=
	if [ -n "$prereq" ] && ! bench_have_prereq "$prereq"; then
		bench_skip=$((bench_skip + 1))
		echo "ok $bench_count - $label # SKIP missing $missing"
		return
	fi
	local dir=$RESULTS/$bench_count out=- rat='' bad=''
	local -A txt=() num=() rc=()
	mkdir -p "$dir"
	"op_$mode" "$dir" "$@"
	for side in $sides; do
		# a profiled run that failed is worth seeing, nothing to compare
		[ "$mode" = time ] || [ "${rc[$side]:-0}" -eq 0 ] ||
			txt[$side]+=" rc ${rc[$side]}"
		if [ "$mode" = time ]; then
			cells+=$(printf '  %-4s %-22s' "$side" "${txt[$side]:-?}")
		else
			cells+=$(printf '  %s' "${txt[$side]:-?}")
		fi
		printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$side" "$mode${tool:+/$tool}" \
			"${num[$side]:-}" "${txt[$side]:-}" >>"$RESULTS.tsv"
	done
	if [ -n "$bad" ]; then
		status="not ok" note=" # $bad"
	elif [ "$expect" = diff ] && [ "$mode" = time ]; then
		if [ "$out" = DIFF ]; then
			status="not ok" note=" # TODO known diff"
		else
			status=ok note=" # TODO known diff vanished"
		fi
	elif [ "$out" = DIFF ]; then
		status="not ok"
	else
		status=ok
	fi
	case $status$note in
	ok) bench_ok=$((bench_ok + 1)) ;;
	*vanished) bench_fixed=$((bench_fixed + 1)) ;;
	*TODO*) bench_known=$((bench_known + 1)) ;;
	*) bench_fail=$((bench_fail + 1)) ;;
	esac
	if [ "$mode" = time ]; then
		printf '%s %d - %-24s%s  %s %s%s\n' "$status" "$bench_count" \
			"$label" "$cells" "$rat" "$out" "$note"
	else
		printf '%s %d - %-24s%s%s\n' "$status" "$bench_count" "$label" \
			"$cells" "$note"
		for side in $sides; do
			[ "$top" -eq 0 ] || [ ! -s "$dir/$side.top" ] ||
				sed "s/^/#   /" "$dir/$side.top"
		done
	fi
	if [ "$status" = "not ok" ] && [ -z "$note" ] || [ -n "$bad" ]; then
		[ "$mode" != time ] || echo "#   diff -u $dir/c.out $dir/puck.out"
		[ -z "$immediate" ] || { bench_done; }
	fi
}

bench_op () {
	bench_run_ same "$@"
}

bench_expect_diff () {
	bench_run_ diff "$@"
}

bench_done () {
	echo "# passed $bench_ok, failed $bench_fail, known diff $bench_known," \
		"vanished $bench_fixed, skipped $bench_skip"
	echo "1..$bench_count"
	[ "$bench_fail" -eq 0 ]
	exit
}

overhead=0
[ "$mode" != time ] || calibrate
echo "# $bench_name: ${bench_description:-}"
if [ "$mode" = time ]; then
	echo "# time, $runs runs, sides: $sides, overhead $(fmt_us "$overhead")"
else
	echo "# $mode${tool:+/$tool} of $sides${top:+, top $top}"
fi
case " $sides " in *" c "*) echo "# c    $BENCH_C" ;; esac
case " $sides " in *" puck "*) echo "# puck $BENCH_PUCK" ;; esac
