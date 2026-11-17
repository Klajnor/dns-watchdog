#!/bin/sh
# Run with BusyBox ash or another shell supporting local (e.g. dash).
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DNS_WATCHDOG_SOURCE_ONLY=1
. "$ROOT/dns-watchdog.sh"

TESTS=0
LOG=''
RECOVERIES=0
MOCK_TIME=1000
MOCK_STATUS=0
MOCK_RESULT=0
MOCK_OUTPUT=''
MOCK_DIG_AVAILABLE=0
MOCK_NSLOOKUP_AVAILABLE=1

log_message() { LOG="${LOG}${LOG:+
}$*"; }
monotonic_seconds() { printf '%s\n' "$MOCK_TIME"; }
new_nonce() { printf '%s\n' '12345678-1234-1234-1234-123456789abc'; }
restart_interface() { RECOVERIES=$((RECOVERIES + 1)); return "$MOCK_RESULT"; }
sleep() { :; }

command_available() {
	case "$1" in
		dig) [ "$MOCK_DIG_AVAILABLE" -eq 1 ] ;;
		nslookup) [ "$MOCK_NSLOOKUP_AVAILABLE" -eq 1 ] ;;
		flock|ubus|ifup|timeout) return 1 ;;
		*) command -v "$1" >/dev/null 2>&1 ;;
	esac
}

run_with_timeout() {
	[ "$1" = "$QUERY_TIMEOUT" ] || return 99
	case "$2" in
		nslookup)
			[ "$3" = "-type=$QUERY_TYPE" ] && [ "$5" = "$DNS_SERVER" ] || return 99
			case "$4" in *.) ;; *) return 99 ;; esac
			;;
		dig)
			[ "$#" -eq 12 ] && [ "$3" = '-r' ] && [ "$4" = "@$DNS_SERVER" ] &&
				[ "$6" = "$QUERY_TYPE" ] && [ "$7" = "+time=$QUERY_TIMEOUT" ] &&
				[ "$8" = '+tries=1' ] && [ "$9" = '+nosearch' ] || return 99
			case "$5" in *.) ;; *) return 99 ;; esac
			shift 9
			[ "$1" = '+noall' ] && [ "$2" = '+comments' ] && [ "$3" = '+answer' ] || return 99
			;;
		*) return 99 ;;
	esac
	printf '%s\n' "$MOCK_OUTPUT"
	return "$MOCK_STATUS"
}

assert_eq() {
	if [ "$1" != "$2" ]; then
		printf 'FAIL: %s: expected <%s>, got <%s>\n' "$3" "$2" "$1" >&2
		exit 1
	fi
	TESTS=$((TESTS + 1))
}

assert_ok() {
	local description="$1"
	shift
	if ! "$@"; then
		printf 'FAIL: %s\n' "$description" >&2
		exit 1
	fi
	TESTS=$((TESTS + 1))
}

assert_fails() {
	local description="$1"
	shift
	if "$@"; then
		printf 'FAIL: %s (unexpected success)\n' "$description" >&2
		exit 1
	fi
	TESTS=$((TESTS + 1))
}

reset_test() {
	set_defaults
	DNS_CLIENT=nslookup
	validate_config
	reset_window
	NEXT_RECOVERY=0
	MOCK_TIME=1000
	RECOVERIES=0
	MOCK_STATUS=0
	MOCK_RESULT=0
	MOCK_DIG_AVAILABLE=0
	MOCK_NSLOOKUP_AVAILABLE=1
	LOG=''
	DRY_RUN=0
	SETTLE_TIME=0
}

reset_test
assert_eq "$DOMAIN_COUNT" 3 'three configured domains'
assert_eq "$(query_name example.org)" 'example.org.' 'absolute DNS name'
assert_eq "$(query_name example.org.)" 'example.org.' 'no duplicate trailing dot'
assert_eq "$(query_name '{nonce}.dnscheck.example.org')" \
	'12345678-1234-1234-1234-123456789abc.dnscheck.example.org.' 'unique wildcard name'
assert_ok 'valid nonce domain' valid_domain '{nonce}.dnscheck.example.org'
assert_fails 'reject invalid placeholder' valid_domain '{nonce}.bad_domain.org'
assert_fails 'reject empty label' valid_domain 'example..org'
assert_fails 'reject leading dash' valid_domain '-example.org'
assert_fails 'reject empty domain' valid_domain ''
LONG_SUFFIX="$(printf '%063d.%063d.%063d.%050d.org' 0 0 0 0)"
assert_ok 'long non-wildcard name within DNS limit' valid_domain "$LONG_SUFFIX"
assert_fails 'reserve length for expanded UUID' valid_domain "{nonce}.$LONG_SUFFIX"

MOCK_OUTPUT='Server: 127.0.0.1
Address: 127.0.0.1#53

Non-authoritative answer:
Name: example.org
Address: 203.0.113.5'
assert_ok 'successful A answer' probe_domain 'example.org.'
MOCK_OUTPUT='Server: 127.0.0.1
Address: 127.0.0.1#53

Name: example.org
Address 1: 203.0.113.5'
assert_ok 'numbered BusyBox address' probe_domain 'example.org.'
QUERY_TYPE=AAAA
MOCK_OUTPUT='Server: 127.0.0.1
Address: 127.0.0.1#53

Name: example.org
Address: 2001:db8::5'
assert_ok 'successful AAAA answer' probe_domain 'example.org.'
QUERY_TYPE=A
MOCK_STATUS=137
assert_fails 'timeout is failure even if output contains an address' probe_domain 'example.org.'
MOCK_STATUS=0
MOCK_OUTPUT='Server: 127.0.0.1
Address: 127.0.0.1#53

Non-authoritative answer:'
assert_fails 'server address is not an answer (NODATA)' probe_domain 'example.org.'
MOCK_OUTPUT='Server: 127.0.0.1
Address: 127.0.0.1#53
example.org canonical name = missing.example.net.'
assert_fails 'CNAME without address is a failure' probe_domain 'example.org.'
MOCK_STATUS=1
MOCK_OUTPUT="** server can't find example.org: SERVFAIL"
assert_fails 'SERVFAIL is failure' probe_domain 'example.org.'
MOCK_OUTPUT="** server can't find example.org: NXDOMAIN"
assert_fails 'unexpected NXDOMAIN is failure' probe_domain 'example.org.'

reset_test
DNS_CLIENT=auto
MOCK_DIG_AVAILABLE=1
MOCK_NSLOOKUP_AVAILABLE=0
select_dns_client
assert_eq "$DNS_CLIENT" dig 'auto prefers dig without requiring nslookup'
MOCK_OUTPUT=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; ANSWER SECTION:
example.org. 120 IN A 203.0.113.5'
assert_ok 'dig NOERROR with A record' probe_domain 'example.org.'
QUERY_TYPE=AAAA
assert_fails 'dig must return the requested record type' probe_domain 'example.org.'
MOCK_OUTPUT=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; ANSWER SECTION:
example.org. 120 IN AAAA 2001:db8::5'
assert_ok 'dig NOERROR with AAAA record' probe_domain 'example.org.'
QUERY_TYPE=A
MOCK_OUTPUT=';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1234
;; ANSWER SECTION:
example.org. 120 IN A 203.0.113.5'
assert_fails 'dig exit zero does not hide SERVFAIL' probe_domain 'example.org.'
MOCK_OUTPUT=';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1234'
assert_fails 'dig exit zero does not hide NXDOMAIN' probe_domain 'example.org.'
MOCK_OUTPUT=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234'
assert_fails 'dig NODATA is a failed positive probe' probe_domain 'example.org.'
MOCK_OUTPUT=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; ADDITIONAL SECTION:
ns.example.org. 120 IN A 203.0.113.5'
assert_fails 'dig glue is not an address answer' probe_domain 'example.org.'
MOCK_OUTPUT=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; ANSWER SECTION:
example.org. 120 IN CNAME target.example.net.'
assert_fails 'dig CNAME alone is not an address answer' probe_domain 'example.org.'
MOCK_OUTPUT=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; ANSWER SECTION:
example.org. 120 IN CNAME target.example.net.
target.example.net. 120 IN A 203.0.113.5'
assert_ok 'dig accepts CNAME resolved to an address' probe_domain 'example.org.'
MOCK_STATUS=9
assert_fails 'dig timeout/nonzero status is a failure' probe_domain 'example.org.'
DNS_CLIENT=auto
MOCK_DIG_AVAILABLE=0
MOCK_NSLOOKUP_AVAILABLE=1
select_dns_client
assert_eq "$DNS_CLIENT" nslookup 'auto falls back to nslookup'
missing_explicit_dig() { ( DNS_CLIENT=dig; select_dns_client ); }
assert_fails 'explicit missing dig does not silently switch clients' missing_explicit_dig

reset_test
record_round 3
record_round 3
record_round 3
assert_fails 'wait for a full window' should_recover
record_round 0
assert_eq "$WINDOW_ERRORS" 9 'nine failed queries'
assert_eq "$WINDOW_QUERIES" 12 'twelve total queries'
assert_fails 'exactly 75 percent is not greater than 75' should_recover
record_round 3
assert_eq "$WINDOW_ERRORS" 9 'oldest round evicted'
record_round 3
record_round 3
record_round 1
assert_eq "$WINDOW_ERRORS" 10 'ten failures in window'
assert_ok '10/12 is strictly above threshold' should_recover
maybe_recover
assert_eq "$RECOVERIES" 1 'one recovery'
assert_eq "$ROUND_COUNT" 0 'history cleared after recovery'
assert_eq "$NEXT_RECOVERY" 1300 'five minute monotonic cooldown'

record_round 3
record_round 3
record_round 3
record_round 3
MOCK_TIME=1299
maybe_recover
assert_eq "$RECOVERIES" 1 'cooldown blocks a second recovery'
assert_eq "$ROUND_COUNT" 4 'continue collecting during cooldown'
MOCK_TIME=1300
maybe_recover
assert_eq "$RECOVERIES" 2 'allow recovery at cooldown boundary'

reset_test
record_round 2
record_round 2
record_round 2
record_round 2
assert_fails 'one working domain per round prevents false recovery' should_recover

reset_test
WINDOW_ROUNDS=5
record_round 3
record_round 3
record_round 3
record_round 3
record_round 0
assert_eq "$WINDOW_ERRORS" 12 '80 percent historical failures'
assert_fails 'do not restart when latest round is already healthy' should_recover

reset_test
DRY_RUN=1
record_round 3
record_round 3
record_round 3
record_round 3
maybe_recover
assert_eq "$RECOVERIES" 0 'dry run never changes interface'
assert_eq "$NEXT_RECOVERY" 1300 'dry run applies the same cooldown'
case "$LOG" in *'DRY RUN: would restart wan'*) ;; *) printf 'Missing dry-run log\n' >&2; exit 1 ;; esac

reset_test
MOCK_RESULT=1
record_round 3
record_round 3
record_round 3
record_round 3
maybe_recover
assert_eq "$RECOVERIES" 1 'failed recovery attempted only once'
assert_eq "$NEXT_RECOVERY" 1300 'failed action is rate limited'

invalid_threshold() { ( ERROR_THRESHOLD=100; validate_config ); }
invalid_timeout() { ( QUERY_TIMEOUT=0; validate_config ); }
invalid_leading_zero() { ( CHECK_INTERVAL=08; validate_config ); }
invalid_dns_server() { ( DNS_SERVER=localhost; validate_config ); }
invalid_dns_octet() { ( DNS_SERVER=127.0.0.999; validate_config ); }
invalid_domains() { ( DOMAINS=''; validate_config ); }
invalid_interface() { ( INTERFACE='wan;reboot'; validate_config ); }
assert_fails 'reject impossible threshold' invalid_threshold
assert_fails 'reject unbounded/zero timeout' invalid_timeout
assert_fails 'reject octal-looking numbers' invalid_leading_zero
assert_fails 'DNS server must not need DNS itself' invalid_dns_server
assert_fails 'reject invalid IP address' invalid_dns_octet
assert_fails 'reject no domains' invalid_domains
assert_fails 'reject unsafe interface name' invalid_interface

# CLI integration: --check must work without timeout/netifd commands,
# even with a configuration that explicitly permits real recovery.
reset_test
MOCK_OUTPUT='Name: example.org
Address: 203.0.113.5'
assert_ok 'CLI diagnostic success with real recovery enabled in config' \
	main --config "$ROOT/tests/fixtures/check.conf" --check
assert_eq "$DRY_RUN" 0 'fixture really enables recovery'
assert_eq "$RECOVERIES" 0 'CLI check never recovers'
MOCK_STATUS=1
MOCK_OUTPUT='SERVFAIL'
assert_fails 'CLI diagnostic returns failure for DNS errors' \
	main --config "$ROOT/tests/fixtures/check.conf" --check
assert_eq "$RECOVERIES" 0 'failed CLI check never recovers either'
MOCK_STATUS=0
MOCK_OUTPUT='Name: example.org
Address: 203.0.113.5'
relative_config_check() { ( cd "$ROOT"; main --config dns-watchdog.conf --check ); }
assert_ok 'bare config filename is read from current directory' relative_config_check

reset_test
MOCK_DIG_AVAILABLE=1
MOCK_NSLOOKUP_AVAILABLE=0
MOCK_OUTPUT=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; ANSWER SECTION:
example.org. 120 IN A 203.0.113.5'
assert_ok 'CLI works with only dig, without nslookup or timeout' \
	main --config "$ROOT/tests/fixtures/check-dig.conf" --check
assert_eq "$DNS_CLIENT" dig 'CLI selects dig'
assert_eq "$RECOVERIES" 0 'dig diagnostic never recovers'

printf 'PASS: %s assertions\n' "$TESTS"
