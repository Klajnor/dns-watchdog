#!/bin/sh
# Real subprocess tests: no DNS queries or network recovery commands.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DNS_WATCHDOG_SOURCE_ONLY=1
. "$ROOT/dns-watchdog.sh"

TESTS=0
assert_eq() {
	if [ "$1" != "$2" ]; then
		printf 'FAIL: %s: expected <%s>, got <%s>\n' "$3" "$2" "$1" >&2
		exit 1
	fi
	TESTS=$((TESTS + 1))
}

# An accidental use of the external command must fail this test, not pass
# just because timeout happens to be installed on the test machine.
timeout() { printf 'External timeout must not be used\n' >&2; return 99; }

started="$(date +%s)"
output="$(run_with_timeout 5 printf '%s' 'fast result')"
elapsed=$(( $(date +%s) - started ))
assert_eq "$output" 'fast result' 'preserve stdout'
[ "$elapsed" -lt 4 ] || { printf 'FAIL: fast command waited for timer\n' >&2; exit 1; }
TESTS=$((TESTS + 1))

emit_and_fail() {
	printf 'stdout'
	printf 'stderr' >&2
	return 7
}
if output="$(run_with_timeout 5 emit_and_fail 2>&1)"; then status=0; else status=$?; fi
assert_eq "$status" 7 'preserve command exit status'
assert_eq "$output" 'stdoutstderr' 'preserve stdout and stderr without timer noise'

started="$(date +%s)"
if run_with_timeout 1 sleep 10; then status=0; else status=$?; fi
elapsed=$(( $(date +%s) - started ))
assert_eq "$status" 137 'kill a command that exceeds its deadline'
[ "$elapsed" -lt 5 ] || { printf 'FAIL: deadline did not stop command\n' >&2; exit 1; }
TESTS=$((TESTS + 1))

# A completed command must also cancel/reap its sleeping timer promptly.
started="$(date +%s)"
iteration=0
while [ "$iteration" -lt 5 ]; do
	run_with_timeout 5 printf ''
	iteration=$((iteration + 1))
done
elapsed=$(( $(date +%s) - started ))
[ "$elapsed" -lt 4 ] || { printf 'FAIL: timer cleanup delayed commands\n' >&2; exit 1; }
TESTS=$((TESTS + 1))

printf 'PASS: %s real deadline assertions\n' "$TESTS"
