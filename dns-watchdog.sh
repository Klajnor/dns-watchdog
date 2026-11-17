#!/bin/sh
# DNS health checks for OpenWrt / BusyBox ash. No state is written to flash.

set -f
LC_ALL=C
export LC_ALL

set_defaults() {
	INTERFACE='wan'
	DNS_SERVER='127.0.0.1'
	DOMAINS='openwrt.org www.cloudflare.com www.wikipedia.org'
	DNS_CLIENT='auto'
	QUERY_TYPE='A'
	CHECK_INTERVAL=15
	QUERY_TIMEOUT=3
	WINDOW_ROUNDS=4
	ERROR_THRESHOLD=75
	COOLDOWN=300
	STARTUP_DELAY=60
	SETTLE_TIME=30
	DRY_RUN=1
	CHECK_ONLY=0
}

log_message() {
	local level="$1"
	shift
	if command -v logger >/dev/null 2>&1; then
		logger -p "daemon.$level" -t dns-watchdog -- "$*"
	else
		printf '%s\n' "$*" >&2
		return 0
	fi
	if [ "$CHECK_ONLY" -eq 1 ] || [ -t 2 ]; then
		printf '%s: %s\n' "$level" "$*" >&2
	fi
}

die() {
	log_message err "$*"
	exit 2
}

command_available() {
	command -v "$1" >/dev/null 2>&1
}

require_command() {
	command_available "$1" || die "Required command not found: $1"
}

select_dns_client() {
	if [ "$DNS_CLIENT" = auto ]; then
		if command_available dig; then
			DNS_CLIENT='dig'
		else
			DNS_CLIENT='nslookup'
		fi
	fi
	require_command "$DNS_CLIENT"
}

validate_integer() {
	local name="$1" value="$2" minimum="$3" maximum="$4"
	case "$value" in
		''|*[!0-9]*|0[0-9]*) die "Invalid $name: use an integer from $minimum to $maximum (no leading zeros)" ;;
	esac
	[ "${#value}" -le 6 ] || die "Value too large: $name"
	[ "$value" -ge "$minimum" ] && [ "$value" -le "$maximum" ] ||
		die "Invalid $name: expected $minimum..$maximum"
}

valid_domain() {
	local domain="${1%.}" maximum=253
	case "$domain" in
		'{nonce}.'*) domain="${domain#'{nonce}.'}"; maximum=216 ;;
	esac
	printf '%s\n' "$domain" | awk -F . -v maximum="$maximum" '
		length($0) > maximum || NF < 2 { exit 1 }
		{
			for (i = 1; i <= NF; i++) {
				if (length($i) > 63 || $i !~ /^[A-Za-z0-9-]+$/ ||
				    $i ~ /^-/ || $i ~ /-$/) exit 1
			}
		}'
}

validate_config() {
	case "$INTERFACE" in
		''|*[!A-Za-z0-9_]*) die 'INTERFACE must be a logical OpenWrt interface name, e.g. wan' ;;
	esac
	# Use a literal IPv4 DNS server, never a hostname needing its own lookup.
	printf '%s\n' "$DNS_SERVER" | awk -F . '
		NF != 4 { exit 1 }
		{
			for (i = 1; i <= NF; i++) {
				if ($i !~ /^[0-9]+$/ || length($i) > 3 || $i + 0 > 255 ||
				    (length($i) > 1 && substr($i, 1, 1) == "0")) exit 1
			}
		}' || die 'DNS_SERVER must be a literal IPv4 address, e.g. 127.0.0.1'
	case "$QUERY_TYPE" in A|AAAA) ;; *) die 'QUERY_TYPE must be A or AAAA' ;; esac
	case "$DNS_CLIENT" in auto|dig|nslookup) ;; *) die 'DNS_CLIENT must be auto, dig or nslookup' ;; esac
	validate_integer CHECK_INTERVAL "$CHECK_INTERVAL" 1 86400
	validate_integer QUERY_TIMEOUT "$QUERY_TIMEOUT" 1 60
	validate_integer WINDOW_ROUNDS "$WINDOW_ROUNDS" 1 100
	validate_integer ERROR_THRESHOLD "$ERROR_THRESHOLD" 0 99
	validate_integer COOLDOWN "$COOLDOWN" 1 86400
	validate_integer STARTUP_DELAY "$STARTUP_DELAY" 0 86400
	validate_integer SETTLE_TIME "$SETTLE_TIME" 0 3600
	validate_integer DRY_RUN "$DRY_RUN" 0 1
	DOMAIN_COUNT=0
	local domain
	for domain in $DOMAINS; do
		valid_domain "$domain" || die "Invalid domain: $domain"
		DOMAIN_COUNT=$((DOMAIN_COUNT + 1))
	done
	[ "$DOMAIN_COUNT" -gt 0 ] && [ "$DOMAIN_COUNT" -le 20 ] ||
		die 'DOMAINS must contain 1..20 space-separated DNS names'
}

monotonic_seconds() {
	local uptime unused
	IFS=' ' read -r uptime unused < /proc/uptime || return 1
	printf '%s\n' "${uptime%%.*}"
}

new_nonce() {
	local nonce
	IFS= read -r nonce < /proc/sys/kernel/random/uuid || return 1
	[ -n "$nonce" ] || return 1
	printf '%s\n' "$nonce"
}

query_name() {
	local domain="${1%.}" nonce
	case "$domain" in
		'{nonce}.'*)
			nonce="$(new_nonce)" || return 1
			domain="$nonce.${domain#'{nonce}.'}"
			;;
	esac
	# A trailing dot prevents search-domain expansion.
	printf '%s.\n' "$domain"
}

# A shell-only deadline: some OpenWrt images do not include timeout at all.
# Use a subshell so cancellation traps cannot replace the daemon's traps.
run_with_timeout() (
	# All variables are already isolated by this function's subshell.
	seconds="$1" command_pid='' timer_pid='' status=0
	shift
	cleanup_timed_command() {
		trap '' HUP INT TERM
		if [ -n "$command_pid" ]; then
			kill -KILL "$command_pid" 2>/dev/null || :
			wait "$command_pid" 2>/dev/null || :
		fi
		if [ -n "$timer_pid" ]; then
			kill -TERM "$timer_pid" 2>/dev/null || :
			wait "$timer_pid" 2>/dev/null || :
		fi
	}
	trap cleanup_timed_command EXIT
	trap 'exit 129' HUP
	trap 'exit 130' INT
	trap 'exit 143' TERM
	"$@" 9>&- &
	command_pid=$!
	(
		sleep_pid=''
		cleanup_timer() {
			if [ -n "$sleep_pid" ]; then
				kill -KILL "$sleep_pid" 2>/dev/null || :
				wait "$sleep_pid" 2>/dev/null || :
			fi
		}
		trap cleanup_timer EXIT
		trap 'exit 0' HUP INT TERM
		sleep "$seconds" &
		sleep_pid=$!
		if wait "$sleep_pid"; then
			sleep_pid=''
			kill -KILL "$command_pid" 2>/dev/null || :
		fi
	# Do not hold a command-substitution output pipe or the daemon lock open.
	) </dev/null >/dev/null 2>&1 9>&- &
	timer_pid=$!
	if wait "$command_pid" 2>/dev/null; then
		status=0
	else
		status=$?
	fi
	command_pid=''
	exit "$status"
)

has_address_answer() {
	if [ "$DNS_CLIENT" = dig ]; then
		# dig exits 0 for many DNS errors. Require NOERROR and a record of
		# the requested type in ANSWER, not a CNAME alone / additional glue.
		awk -v type="$QUERY_TYPE" '
			/^;; ->>HEADER<<-/ {
				noerror = 0; found = 0; answer = 0
				for (i = 1; i < NF; i++)
					if ($i == "status:" && $(i + 1) == "NOERROR,") noerror = 1
				next
			}
			/^;; ANSWER SECTION:/ { answer = 1; next }
			/^;;/ { answer = 0; next }
			answer && NF >= 5 && $3 == "IN" && $4 == type { found = 1 }
			END { exit !(noerror && found) }'
	else
		# nslookup may exit 0 for NODATA. Do not mistake the DNS server's
		# Address line for a successful answer.
		awk '
			/^Name:[[:space:]]/ { answer = 1; next }
			answer && /^Address([[:space:]][0-9]+)?:[[:space:]]/ { found = 1 }
			END { exit !found }'
	fi
}

probe_domain() {
	local output status
	if [ "$DNS_CLIENT" = dig ]; then
		# -r ignores ~/.digrc, keeping the parsed output predictable.
		# Native limits avoid retries; the shell deadline also bounds TCP fallback.
		if output="$(run_with_timeout "$QUERY_TIMEOUT" dig -r "@$DNS_SERVER" "$1" "$QUERY_TYPE" "+time=$QUERY_TIMEOUT" +tries=1 +nosearch +noall +comments +answer 2>&1)"; then
			status=0
		else
			status=$?
		fi
	else
		if output="$(run_with_timeout "$QUERY_TIMEOUT" nslookup "-type=$QUERY_TYPE" "$1" "$DNS_SERVER" 2>&1)"; then
			status=0
		else
			status=$?
		fi
	fi
	if [ "$status" -eq 0 ] && printf '%s\n' "$output" | has_address_answer; then
		if [ "$CHECK_ONLY" -eq 1 ]; then
			log_message notice "OK: $1 via $DNS_SERVER ($QUERY_TYPE, $DNS_CLIENT)"
		fi
		return 0
	fi
	log_message warning "DNS failure: $1 via $DNS_SERVER ($QUERY_TYPE), $DNS_CLIENT status=$status; timeout, DNS error or no address"
	if [ "$CHECK_ONLY" -eq 1 ]; then
		printf '%s\n' "$output" >&2
	fi
	return 1
}

check_round() {
	local domain name
	ROUND_ERRORS=0
	for domain in $DOMAINS; do
		name="$(query_name "$domain")" || die "Cannot generate a query name for $domain"
		if ! probe_domain "$name"; then
			ROUND_ERRORS=$((ROUND_ERRORS + 1))
		fi
	done
}

reset_window() {
	HISTORY=''
	ROUND_COUNT=0
	WINDOW_ERRORS=0
	WINDOW_QUERIES=0
	ROUND_ERRORS=0
}

record_round() {
	local errors
	ROUND_ERRORS="$1"
	HISTORY="${HISTORY:+$HISTORY }$ROUND_ERRORS"
	set -- $HISTORY
	if [ "$#" -gt "$WINDOW_ROUNDS" ]; then
		shift
	fi
	HISTORY="$*"
	ROUND_COUNT="$#"
	WINDOW_ERRORS=0
	for errors in "$@"; do
		WINDOW_ERRORS=$((WINDOW_ERRORS + errors))
	done
	WINDOW_QUERIES=$((ROUND_COUNT * DOMAIN_COUNT))
}

should_recover() {
	# Wait for a complete window, and do not reset an already healthy round.
	[ "$ROUND_COUNT" -ge "$WINDOW_ROUNDS" ] &&
		[ "$ROUND_ERRORS" -gt 0 ] &&
		[ "$((WINDOW_ERRORS * 100))" -gt "$((ERROR_THRESHOLD * WINDOW_QUERIES))" ]
}

interface_exists() {
	run_with_timeout 10 ubus -t 5 call "network.interface.$INTERFACE" status >/dev/null 2>&1
}

restart_interface() {
	interface_exists || {
		log_message err "Cannot find logical interface $INTERFACE in netifd; no restart performed"
		return 1
	}
	# OpenWrt ifup requests down + up through netifd. Never restart all LAN/WAN.
	run_with_timeout 20 ifup "$INTERFACE"
}

maybe_recover() {
	local now
	should_recover || return 0
	now="$(monotonic_seconds)" || die 'Cannot read monotonic clock'
	[ "$now" -ge "$NEXT_RECOVERY" ] || return 0
	if [ "$DRY_RUN" -eq 1 ]; then
		log_message warning "DRY RUN: would restart $INTERFACE: $WINDOW_ERRORS/$WINDOW_QUERIES DNS failures (strictly > $ERROR_THRESHOLD%); cooldown ${COOLDOWN}s"
	else
		log_message warning "Restarting $INTERFACE: $WINDOW_ERRORS/$WINDOW_QUERIES DNS failures (strictly > $ERROR_THRESHOLD%)"
		if ! restart_interface; then
			log_message err "Interface recovery failed for $INTERFACE; cooldown still applies"
		fi
	fi
	# Apply cooldown even to a failed action / dry run. Use uptime, not wall
	# clock: NTP adjustments must not bypass the rate limit.
	now="$(monotonic_seconds)" || die 'Cannot read monotonic clock'
	NEXT_RECOVERY=$((now + COOLDOWN))
	reset_window
	if [ "$DRY_RUN" -eq 0 ] && [ "$SETTLE_TIME" -gt 0 ]; then
		sleep "$SETTLE_TIME"
	fi
}

usage() {
	cat <<'EOF'
Usage: dns-watchdog [--config FILE] [--check] [--dry-run]
  --config FILE  Shell configuration (default: /etc/dns-watchdog.conf)
  --check        One diagnostic round, NEVER restart anything.
                 Exit 0: all names resolved, 1: DNS failures, 2: setup error.
  --dry-run      Force logging-only mode, regardless of the configuration.
EOF
}

main() {
	local config_file='/etc/dns-watchdog.conf' check_only=0 force_dry_run=0 command
	local round_start now delay
	set_defaults
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--config)
				[ "$#" -ge 2 ] || die '--config requires a file path'
				config_file="$2"
				shift 2
				;;
			--check) check_only=1; shift ;;
			--dry-run) force_dry_run=1; shift ;;
			--help|-h) usage; return 0 ;;
			*) die "Unknown option: $1" ;;
		esac
	done
	CHECK_ONLY="$check_only"
	# dot searches PATH for bare filenames; explicitly use the current dir.
	case "$config_file" in */*) ;; *) config_file="./$config_file" ;; esac
	[ -r "$config_file" ] || die "Cannot read configuration: $config_file"
	# Configuration is trusted shell code; keep it writable by root only.
	. "$config_file"
	CHECK_ONLY="$check_only"
	[ "$force_dry_run" -eq 0 ] || DRY_RUN=1
	for command in awk sleep; do
		require_command "$command"
	done
	validate_config
	select_dns_client
	if [ "$CHECK_ONLY" -eq 1 ]; then
		check_round
		log_message notice "Diagnostic result: $ROUND_ERRORS/$DOMAIN_COUNT DNS failures; no recovery actions"
		[ "$ROUND_ERRORS" -eq 0 ]
		return "$?"
	fi
	for command in flock ubus ifup; do
		require_command "$command"
	done
	exec 9>/var/run/dns-watchdog.lock || die 'Cannot open daemon lock'
	flock -n 9 || die 'Another dns-watchdog daemon is already running'
	interface_exists || die "Unknown / unavailable logical interface: $INTERFACE"
	trap 'exit 0' INT TERM
	reset_window
	NEXT_RECOVERY=0
	log_message notice "Started: client=$DNS_CLIENT, resolver=$DNS_SERVER, interface=$INTERFACE, window=$WINDOW_ROUNDS x $DOMAIN_COUNT queries, threshold > $ERROR_THRESHOLD%, dry_run=$DRY_RUN"
	[ "$STARTUP_DELAY" -eq 0 ] || sleep "$STARTUP_DELAY"
	while :; do
		round_start="$(monotonic_seconds)" || die 'Cannot read monotonic clock'
		check_round
		record_round "$ROUND_ERRORS"
		if [ "$ROUND_ERRORS" -gt 0 ]; then
			log_message warning "Round: $ROUND_ERRORS/$DOMAIN_COUNT failures; window: $WINDOW_ERRORS/$WINDOW_QUERIES ($ROUND_COUNT/$WINDOW_ROUNDS rounds)"
		fi
		maybe_recover
		now="$(monotonic_seconds)" || die 'Cannot read monotonic clock'
		delay=$((CHECK_INTERVAL - (now - round_start)))
		[ "$delay" -gt 0 ] || delay=1
		sleep "$delay"
	done
}

# Allows the test suite to load functions without starting the daemon.
if [ "${DNS_WATCHDOG_SOURCE_ONLY:-0}" != 1 ]; then
	main "$@"
fi
