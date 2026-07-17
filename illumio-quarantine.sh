#!/bin/bash

# ==============================================================================
# 腳本名稱: illumio-quarantine.sh
# 描述:     根據多種條件 (IP、主機名、CIDR、IP 範圍、前綴) 尋找 Illumio Workloads，
#           並在用戶確認後，以指定模式（增加或覆蓋）為匹配到的 'managed' Workloads
#           添加/設置指定的 Label。
# 作者:     Harry
# 日期:     20250419
# 版本:     1.3.2
#
# 依賴套件:
#   - curl:   用於發送 HTTP API 請求。
#   - jq:     用於解析 JSON 響應。
#   - ipcalc: 用於執行 CIDR 網路計算 (必需)。
#
# 使用方法:
#   ./illumio-quarantine.sh
#   腳本將提示輸入搜索條件、Label ID 及更新模式。
#
# !!! SECURITY NOTES !!!
# PCE API credentials loaded by load_credentials() in this order:
#   CLI flags > env vars > --credentials-file > script defaults.
# Never commit credentials to source control. See config/quarantine.conf.example.
# ==============================================================================

# --- 配置 ---
API_VERSION="v2"                         # 要使用的 Illumio API 版本
CURL_OPTS="-s --connect-timeout 10 --max-time 30"  # silent, verify certs by default, 10s connect / 30s total

# Credentials are loaded by load_credentials() after argument parsing.
# Precedence: CLI flags > env vars > --credentials-file > script defaults.
API_USER=""
API_PASS=""
PCE_URL_BASE=""
ORG_ID=""
CURL_AUTH_FILE=""
RESULT_DIR=""

# --- 輔助函數 ---

# @description 將 IPv4 地址字符串轉換為其 32 位整數表示。
# @param $1 string IPv4 地址字符串 (例如: "192.168.1.1")。
# @return integer 整數表示，如果輸入無效則返回 -1。
ip_to_int() {
    local ip=$1
    local o1 o2 o3 o4 o
    IFS=. read -r o1 o2 o3 o4 <<< "$ip"

    for o in "$o1" "$o2" "$o3" "$o4"; do
        # 10# forces base-10 so leading zeros are not parsed as octal
        # ("08" would otherwise be a bash arithmetic error).
        if ! [[ "$o" =~ ^[0-9]{1,3}$ ]] || (( 10#$o > 255 )); then
            echo "-1"; return 1
        fi
    done
    echo $(( (10#$o1 << 24) + (10#$o2 << 16) + (10#$o3 << 8) + 10#$o4 ))
    return 0
}

# @description 檢查給定的 IPv4 地址是否在指定的範圍內 (包含邊界)。
# @param $1 string 要檢查的 IPv4 地址。
# @param $2 string 範圍的起始 IPv4 地址。
# @param $3 string 範圍的結束 IPv4 地址。
# @return integer 如果 IP 在範圍內，退出狀態為 0，否則為 1 (或輸入無效)。
is_in_range() {
    local ip_to_check=$1
    local range_start=$2
    local range_end=$3
    local ip_int check_start_int check_end_int

    ip_int=$(ip_to_int "$ip_to_check")
    check_start_int=$(ip_to_int "$range_start")
    check_end_int=$(ip_to_int "$range_end")

    if [[ "$ip_int" == "-1" || "$check_start_int" == "-1" || "$check_end_int" == "-1" || "$check_start_int" -gt "$check_end_int" ]]; then
        return 1
    fi
    [[ "$ip_int" -ge "$check_start_int" && "$ip_int" -le "$check_end_int" ]]
}

classify_term() {
    local t="$1"
    if [[ "$t" == */* ]]; then echo "cidr"; return; fi
    if is_ipv4_range_dash "$t" || is_ipv4_range_tilde "$t"; then
        echo "range"; return
    fi
    if [[ "$t" == *. && ! "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "prefix"; return
    fi
    if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "ip"; return; fi
    echo "hostname"
}

is_ipv4_range_dash() {
    local t="$1" s e extra s_int e_int
    IFS='-' read -r s e extra <<< "$t"
    [[ -n "$s" && -n "$e" && -z "$extra" ]] || return 1
    s_int=$(ip_to_int "$s" || true)
    e_int=$(ip_to_int "$e" || true)
    [[ "$s_int" != "-1" && "$e_int" != "-1" ]]
}

is_ipv4_range_tilde() {
    local t="$1" s e extra s_int e_int
    IFS='~' read -r s e extra <<< "$t"
    [[ -n "$s" && -n "$e" && -z "$extra" ]] || return 1
    s_int=$(ip_to_int "$s" || true)
    e_int=$(ip_to_int "$e" || true)
    [[ "$s_int" != "-1" && "$e_int" != "-1" ]]
}

# @description Normalize the network part of a CIDR term via ipcalc so a host
#              address like 10.0.0.5/24 matches workloads in 10.0.0.0/24.
# @param $1 CIDR term
# @return prints normalized "network/prefix"; exit 1 if ipcalc rejects it
normalize_cidr() {
    local term="$1" net prefix out
    IFS='/' read -r net prefix <<< "$term"
    out=$(ipcalc -n "${net}/${prefix}" 2>/dev/null) || return 1
    net=$(echo "$out" | grep -E '^(Network:|NETWORK=)' | head -n 1 \
        | sed -E 's/^(Network:|NETWORK=)[[:space:]]*//; s|/.*||; s/[[:space:]]*$//')
    [[ -n "$net" ]] || return 1
    printf '%s/%s' "$net" "$prefix"
}

# @description Validate every search term and normalize in place.
#              A quarantine run must not silently ignore a malformed target:
#              invalid CIDR/IP/range/prefix terms exit 5 instead of matching
#              nothing. Ranges tolerate spaces around the separator, and CIDR
#              terms are rewritten to their network address.
validate_search_terms() {
    local i term t ip prefix s e sep o norm
    for i in "${!SEARCH_TERMS[@]}"; do
        term="${SEARCH_TERMS[$i]}"
        [[ -z "$term" ]] && continue

        # Tolerate spaces around range separators: "10.0.0.1 - 10.0.0.5"
        if [[ "$term" =~ ^[0-9.[:space:]]+[-~][0-9.[:space:]]+$ ]]; then
            term="${term// /}"
            SEARCH_TERMS[$i]="$term"
        fi

        t=$(classify_term "$term")
        case "$t" in
            cidr)
                IFS='/' read -r ip prefix <<< "$term"
                if [[ "$(ip_to_int "$ip")" == "-1" ]] || \
                   ! [[ "$prefix" =~ ^[0-9]{1,2}$ ]] || (( 10#$prefix > 32 )); then
                    echo "ERROR: invalid CIDR target '${term}'" >&2; exit 5
                fi
                norm=$(normalize_cidr "$term") || {
                    echo "ERROR: invalid CIDR target '${term}'" >&2; exit 5
                }
                SEARCH_TERMS[$i]="$norm"
                ;;
            range)
                sep='-'
                [[ "$term" == *~* ]] && sep='~'
                IFS="$sep" read -r s e <<< "$term"
                if (( $(ip_to_int "$s") > $(ip_to_int "$e") )); then
                    echo "ERROR: invalid IP range '${term}' (start > end)" >&2; exit 5
                fi
                ;;
            ip)
                if [[ "$(ip_to_int "$term")" == "-1" ]]; then
                    echo "ERROR: invalid IPv4 target '${term}'" >&2; exit 5
                fi
                ;;
            prefix)
                if ! [[ "$term" =~ ^([0-9]{1,3}\.){1,3}$ ]]; then
                    echo "ERROR: invalid IP-prefix target '${term}'" >&2; exit 5
                fi
                for o in ${term//./ }; do
                    if (( 10#$o > 255 )); then
                        echo "ERROR: invalid IP-prefix target '${term}'" >&2; exit 5
                    fi
                done
                ;;
            hostname)
                # A term made only of digits/dots/range separators that did
                # not parse as IP/CIDR/range is a typo, not a hostname.
                if [[ "$term" =~ ^[0-9.~-]+$ ]]; then
                    echo "ERROR: invalid target '${term}' (not a valid IP/CIDR/range)" >&2; exit 5
                fi
                ;;
        esac
    done
}

load_credentials_file() {
    local creds_file="$1"
    local line key raw value

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        line="$(printf '%s' "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
        [[ -z "$line" || "$line" == \#* ]] && continue

        if [[ "$line" =~ ^export[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"
            raw="${BASH_REMATCH[2]}"
        elif [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"
            raw="${BASH_REMATCH[2]}"
        else
            echo "ERROR: unsupported syntax in credentials file: $creds_file" >&2
            exit 5
        fi

        raw="$(printf '%s' "$raw" | sed -E 's/[[:space:]]+$//')"
        if [[ "$raw" =~ ^\"(.*)\"$ ]]; then
            value="${BASH_REMATCH[1]}"
        elif [[ "$raw" =~ ^\'(.*)\'$ ]]; then
            value="${BASH_REMATCH[1]}"
        else
            if [[ "$raw" =~ [\$\`\(\)\;\&\|\<\>] ]]; then
                echo "ERROR: unsafe unquoted value for ${key} in credentials file: $creds_file" >&2
                exit 5
            fi
            value="$raw"
        fi

        case "$key" in
            API_USER)     API_USER="$value" ;;
            API_PASS)     API_PASS="$value" ;;
            PCE_URL_BASE) PCE_URL_BASE="$value" ;;
            ORG_ID)       ORG_ID="$value" ;;
            *) echo "WARNING: ignoring unknown key '${key}' in credentials file: $creds_file" >&2 ;;
        esac
    done < "$creds_file"
}

load_credentials() {
    local env_has_creds=0
    if [[ -n "${ILLUMIO_QUARANTINE_API_USER:-}" && -n "${ILLUMIO_QUARANTINE_API_PASS:-}" ]]; then
        env_has_creds=1
    fi

    # Auto-discover a credentials file if --credentials-file was not given
    if [[ -z "${CREDENTIALS_FILE:-}" && "$env_has_creds" != "1" ]]; then
        for p in \
            "${HOME}/.config/illumio_quarantine/quarantine.conf" \
            "/etc/illumio_quarantine/quarantine.conf"
        do
            if [[ -r "$p" ]]; then
                CREDENTIALS_FILE="$p"
                break
            fi
        done
    fi

    # Step 1: --credentials-file (lowest of the three non-default sources)
    if [[ -n "${CREDENTIALS_FILE:-}" ]]; then
        if [[ ! -r "$CREDENTIALS_FILE" ]]; then
            echo "ERROR: credentials file not readable: $CREDENTIALS_FILE" >&2
            exit 5
        fi
        load_credentials_file "$CREDENTIALS_FILE"
        if [[ "$(uname)" == "Linux" ]]; then
            local mode
            mode=$(stat -c '%a' "$CREDENTIALS_FILE" 2>/dev/null || echo "000")
            if [[ -n "$mode" && "$mode" != "600" && "$mode" != "400" ]]; then
                echo "WARNING: credentials file $CREDENTIALS_FILE has insecure permissions $mode; recommend chmod 600" >&2
            fi
        fi
    fi

    # Step 2: env (overrides credentials-file when set)
    [[ -n "${ILLUMIO_QUARANTINE_API_USER:-}" ]] && API_USER="$ILLUMIO_QUARANTINE_API_USER"
    [[ -n "${ILLUMIO_QUARANTINE_API_PASS:-}" ]] && API_PASS="$ILLUMIO_QUARANTINE_API_PASS"
    [[ -n "${ILLUMIO_QUARANTINE_PCE_URL:-}" ]] && PCE_URL_BASE="$ILLUMIO_QUARANTINE_PCE_URL"
    [[ -n "${ILLUMIO_QUARANTINE_ORG_ID:-}"  ]] && ORG_ID="$ILLUMIO_QUARANTINE_ORG_ID"

    # Step 3: CLI flag overrides (these are set in the arg parser; only if non-empty)
    [[ -n "${CLI_PCE_URL:-}" ]] && PCE_URL_BASE="$CLI_PCE_URL"
    [[ -n "${CLI_ORG_ID:-}"  ]] && ORG_ID="$CLI_ORG_ID"

    # Step 4: defaults
    [[ -z "$PCE_URL_BASE" ]] && PCE_URL_BASE="https://pce.lab.local:8443"
    [[ -z "$ORG_ID"       ]] && ORG_ID="1"

    # Step 5: missing creds
    if [[ -z "$API_USER" || -z "$API_PASS" ]]; then
        if [[ "${NON_INTERACTIVE:-0}" == "1" ]]; then
            echo "ERROR: API credentials missing (use --credentials-file, env vars, or drop --non-interactive)" >&2
            exit 6
        fi
        [[ -z "$API_USER" ]] && { read -e -p "Illumio API user: " API_USER; }
        [[ -z "$API_PASS" ]] && { read -s -p "Illumio API password: " API_PASS; echo; }
    fi
    [[ -z "$API_USER" || -z "$API_PASS" ]] && exit 6
}

# Remove temp files created by this run (curl auth config, PUT result dir).
# Installed as the EXIT/INT/TERM trap by init_curl_auth_file.
cleanup_tmp_files() {
    [[ -n "$CURL_AUTH_FILE" ]] && rm -f "$CURL_AUTH_FILE"
    [[ -n "$RESULT_DIR" ]] && rm -rf "$RESULT_DIR"
}

# Write API_USER/API_PASS into a 0600 temp file and set up cleanup, so the
# credentials are passed to curl via `-K $CURL_AUTH_FILE` and never appear in
# /proc/<pid>/cmdline (where any local user could read them).
# Trap is installed BEFORE the file is populated so an immediate signal still
# triggers cleanup.
init_curl_auth_file() {
    local old_umask
    old_umask=$(umask)
    umask 077
    CURL_AUTH_FILE=$(mktemp "${TMPDIR:-/tmp}/iq_curlauth_XXXXXX") || {
        umask "$old_umask"
        echo "ERROR: failed to create curl auth temp file" >&2
        exit 1
    }
    umask "$old_umask"
    # Defensive chmod in case mktemp ignored umask on some platform.
    chmod 600 "$CURL_AUTH_FILE" 2>/dev/null || true
    trap 'cleanup_tmp_files' EXIT
    trap 'cleanup_tmp_files; trap - INT TERM; kill -INT $$' INT
    trap 'cleanup_tmp_files; trap - INT TERM; kill -TERM $$' TERM
    # curl -K config: `user = "user:pass"` with embedded quotes in the value
    # must be backslash-escaped per curl(1).
    local esc_user="${API_USER//\\/\\\\}"
    esc_user="${esc_user//\"/\\\"}"
    local esc_pass="${API_PASS//\\/\\\\}"
    esc_pass="${esc_pass//\"/\\\"}"
    printf 'user = "%s:%s"\n' "$esc_user" "$esc_pass" > "$CURL_AUTH_FILE"
}

# Target label state — resolved by resolve_target_label()
TARGET_LABEL_HREF=""
TARGET_LABEL_KEY=""
TARGET_LABEL_VALUE=""
SAME_KEY_HREFS_JSON="[]"

_urlenc() {
    printf '%s' "$1" | jq -sRr @uri
}

# The PCE silently truncates synchronous collection GETs to the latest 500
# results (larger collections require async jobs via `Prefer: respond-async`).
PCE_SYNC_GET_MAX=500

# @description GET a PCE URL, capturing body and HTTP status.
#              Detects auth failure by status code (the PCE returns 401/403
#              with a JSON *array* error body, so body-shape sniffing is
#              unreliable). Exits 4 on network failure, 401/403, or any other
#              non-2xx status not listed in $3.
# @param $1 url
# @param $2 context string for error messages
# @param $3 optional space-separated non-2xx statuses to pass through
# Sets: PCE_BODY, PCE_HTTP
pce_get() {
    local url="$1" ctx="$2" allow="${3:-}"
    local out curl_ec s
    out=$(curl ${CURL_OPTS} -K "$CURL_AUTH_FILE" \
              -H 'Accept: application/json' \
              -w '\n%{http_code}' "$url")
    curl_ec=$?
    if [[ $curl_ec -ne 0 ]]; then
        echo "ERROR: PCE unreachable (curl exit $curl_ec) at ${ctx}" >&2
        emit_cef "failure" 2>/dev/null || true
        exit 4
    fi
    PCE_HTTP="${out##*$'\n'}"
    PCE_BODY="${out%$'\n'*}"
    if [[ "$PCE_HTTP" == "401" || "$PCE_HTTP" == "403" ]]; then
        echo "ERROR: PCE authentication failed (HTTP ${PCE_HTTP}) at ${ctx}" >&2
        emit_cef "failure" 2>/dev/null || true
        exit 4
    fi
    if [[ "$PCE_HTTP" =~ ^2[0-9][0-9]$ ]]; then
        return 0
    fi
    for s in $allow; do
        [[ "$PCE_HTTP" == "$s" ]] && return 0
    done
    echo "ERROR: PCE returned HTTP ${PCE_HTTP} at ${ctx}" >&2
    emit_cef "failure" 2>/dev/null || true
    exit 4
}

# @description Fail hard when a synchronous collection GET returned
#              PCE_SYNC_GET_MAX items — the result set may be silently
#              truncated by the PCE and a quarantine run on partial data
#              could miss targets.
# @param $1 response body (JSON array)
# @param $2 context string for the error message
check_sync_truncation() {
    local body="$1" ctx="$2" n
    n=$(echo "$body" | jq 'length' 2>/dev/null || echo 0)
    if [[ "$n" -ge "$PCE_SYNC_GET_MAX" ]]; then
        echo "ERROR: PCE returned ${n} items for ${ctx}; synchronous collection GETs are truncated at ${PCE_SYNC_GET_MAX} so results may be incomplete. Refusing to continue — narrow the query or use async GET collections (Prefer: respond-async)." >&2
        emit_cef "failure" 2>/dev/null || true
        exit 4
    fi
}

# @description Escape a value per ArcSight CEF (backslash, pipe, equals, CR, LF, space).
# Also strips control characters (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F) via tr.
cef_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s// /\\ }"
    s="${s//|/\\|}"
    s="${s//=/\\=}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    # Remove control characters: keep only printable ASCII, space, tab, newline
    s=$(printf '%s' "$s" | tr -cd '[:print:]\t\n ')
    printf '%s' "$s"
}

# @description Append one CEF:0 audit line to $AUDIT_FILE using flock for
#              concurrent-writer safety. No-op when $AUDIT_FILE is unset/empty.
# @param $1 outcome: success | partial | no_match | failure
emit_cef() {
    [[ -z "${AUDIT_FILE:-}" ]] && return 0
    local outcome="$1"
    [[ -z "${AUDIT_ID:-}" ]] && AUDIT_ID="qr-$(date -u +%Y-%m-%dT%H-%M-%SZ)-early"
    local epoch_ms; epoch_ms=$(date +%s%3N)
    local pce_host; pce_host="${PCE_URL_BASE#https://}"; pce_host="${pce_host%%/*}"; pce_host="${pce_host%%:*}"
    local esc_reason;  esc_reason=$(cef_escape "${REASON:-}")
    local esc_targets; esc_targets=$(cef_escape "${SEARCH_TERMS_RAW:-}")
    local esc_cid;     esc_cid=$(cef_escape "${CORRELATION_ID:-}")
    local esc_key;     esc_key=$(cef_escape "${TARGET_LABEL_KEY:-}")
    local esc_val;     esc_val=$(cef_escape "${TARGET_LABEL_VALUE:-}")
    local dry;         dry=$([[ "${DRY_RUN:-0}" == 1 ]] && echo true || echo false)
    local updated_ct="${#J_UPDATED[@]}"
    local failed_ct="${#J_FAILED[@]}"

    # Reject symlinks on $AUDIT_FILE and ${AUDIT_FILE}.lock to prevent symlink-redirection attacks
    if [[ -L "$AUDIT_FILE" ]]; then
        echo "WARNING: refusing to write audit: $AUDIT_FILE is a symbolic link" >&2
        return 1
    fi
    if [[ -L "${AUDIT_FILE}.lock" ]]; then
        echo "WARNING: refusing to use audit lock: ${AUDIT_FILE}.lock is a symbolic link" >&2
        return 1
    fi

    local line
    # dry_run uses flexString1: CEF only defines custom strings cs1-cs6.
    line=$(printf 'CEF:0|Illumio|Quarantine|%s|quarantine.action|Illumio Quarantine Action|5|rt=%s dvchost=%s act=%s outcome=%s cs1Label=correlation_id cs1=%s cs2Label=audit_id cs2=%s cs3Label=reason cs3=%s cs4Label=targets cs4=%s cs5Label=label_key cs5=%s cs6Label=label_value cs6=%s cn1Label=updated_count cn1=%d cn2Label=failed_count cn2=%d flexString1Label=dry_run flexString1=%s' \
        "$VERSION" "$epoch_ms" "$pce_host" "${UPDATE_MODE:-}" "$outcome" \
        "$esc_cid" "$AUDIT_ID" "$esc_reason" "$esc_targets" \
        "$esc_key" "$esc_val" \
        "$updated_ct" "$failed_ct" "$dry")

    mkdir -p "$(dirname "$AUDIT_FILE")" 2>/dev/null || true
    local lock="${AUDIT_FILE}.lock"
    touch "$lock"
    (
        flock -x 9
        printf '%s\n' "$line" >> "$AUDIT_FILE"
    ) 9>"$lock"
}

resolve_target_label() {
    local base="${PCE_URL_BASE}/api/${API_VERSION}/orgs/${ORG_ID}"
    if [[ -n "$LABEL_ID" ]]; then
        pce_get "${base}/labels/${LABEL_ID}" "labels/${LABEL_ID}" "404"
        if [[ "$PCE_HTTP" == "404" ]] || \
           ! echo "$PCE_BODY" | jq -e 'type=="object" and has("href")' >/dev/null 2>&1; then
            echo "ERROR: label id ${LABEL_ID} not found" >&2
            exit 5
        fi
        TARGET_LABEL_HREF="/orgs/${ORG_ID}/labels/${LABEL_ID}"
        TARGET_LABEL_KEY=$(echo   "$PCE_BODY" | jq -r '.key')
        TARGET_LABEL_VALUE=$(echo "$PCE_BODY" | jq -r '.value')
    else
        local enc_key
        enc_key=$(_urlenc "$LABEL_KEY")
        pce_get "${base}/labels?key=${enc_key}" "labels?key=${enc_key}"
        if ! echo "$PCE_BODY" | jq -e 'type=="array"' >/dev/null 2>&1; then
            echo "ERROR: PCE response is not a JSON array for labels?key=${enc_key}" >&2
            emit_cef "failure"
            exit 4
        fi
        check_sync_truncation "$PCE_BODY" "labels?key=${LABEL_KEY}"
        TARGET_LABEL_HREF=$(echo "$PCE_BODY" | jq -r --arg v "$LABEL_VALUE" \
            '[.[] | select(.value==$v)][0].href // empty')
        if [[ -z "$TARGET_LABEL_HREF" ]]; then
            echo "ERROR: no label with key=${LABEL_KEY} value=${LABEL_VALUE}" >&2
            exit 5
        fi
        TARGET_LABEL_KEY="$LABEL_KEY"
        TARGET_LABEL_VALUE="$LABEL_VALUE"
    fi

    # Fetch all hrefs sharing TARGET_LABEL_KEY (used by B2 same-key strip)
    local enc_target_key
    enc_target_key=$(_urlenc "$TARGET_LABEL_KEY")
    pce_get "${base}/labels?key=${enc_target_key}" "labels?key=${enc_target_key}"
    if ! echo "$PCE_BODY" | jq -e 'type=="array"' >/dev/null 2>&1; then
        echo "ERROR: PCE response is not a JSON array for labels?key=${enc_target_key}" >&2
        emit_cef "failure"
        exit 4
    fi
    check_sync_truncation "$PCE_BODY" "labels?key=${TARGET_LABEL_KEY}"
    SAME_KEY_HREFS_JSON=$(echo "$PCE_BODY" | jq -c '[.[].href]')
}

# @description Build PUT body, check idempotency, issue PUT, and classify outcome.
#              Designed to run as a background job; writes one JSON result file
#              into $result_dir so the main loop can aggregate after `wait`.
# @param $1 workload_href
# @param $2 hostname_display
# @param $3 existing_labels_json
# @param $4 result_dir
put_one_workload() {
    local workload_href="$1"
    local hostname_display="$2"
    local existing_labels_json="$3"
    local result_dir="$4"

    local put_body
    if [[ "$UPDATE_MODE" == "overwrite" ]]; then
        put_body=$(jq -nc --arg h "$TARGET_LABEL_HREF" \
                        '{labels:[{href:$h}]}')
    else
        put_body=$(jq -nc \
            --argjson existing "$existing_labels_json" \
            --argjson same_key "$SAME_KEY_HREFS_JSON" \
            --arg     h        "$TARGET_LABEL_HREF" \
            '{labels: (
                  ($existing | map(select(.href as $x | ($same_key | index($x)) | not)))
                + [{href:$h}]
            )}')
    fi

    local result_path
    result_path="$result_dir/$(echo "$workload_href" | tr / _).json"

    if [[ -z "$put_body" ]]; then
        jq -nc --arg href "$workload_href" --arg hn "$hostname_display" \
               --arg e   "failed to build PUT body" \
            '{kind:"failed",href:$href,hostname:$hn,http:0,error:$e}' > "$result_path"
        return 0
    fi

    # Idempotent skip (append only): identical label set → record "skipped"
    if [[ "$UPDATE_MODE" == "append" ]]; then
        local before after
        before=$(echo "$existing_labels_json" | jq -c 'sort_by(.href)')
        after=$(echo  "$put_body"             | jq -c '.labels | sort_by(.href)')
        if [[ "$before" == "$after" ]]; then
            jq -nc --arg href "$workload_href" --arg hn "$hostname_display" \
                '{kind:"skipped",href:$href,hostname:$hn}' > "$result_path"
            return 0
        fi
    fi

    local http_code curl_ec
    if [[ "$DRY_RUN" == "1" ]]; then
        http_code="000"; curl_ec=0
    else
        http_code=$(curl ${CURL_OPTS} -X PUT \
            -K "$CURL_AUTH_FILE" \
            -H "Content-Type: application/json" \
            -H "Accept: application/json" \
            -d "$put_body" -o /dev/null -w "%{http_code}" \
            "${PCE_URL_BASE}/api/${API_VERSION}${workload_href}")
        curl_ec=$?
    fi

    if [[ "$DRY_RUN" == "1" ]]; then
        jq -nc --arg href "$workload_href" --arg hn "$hostname_display" \
            '{kind:"updated",dry_run:true,href:$href,hostname:$hn}' > "$result_path"
    elif [[ $curl_ec -ne 0 ]]; then
        jq -nc --arg href "$workload_href" --arg hn "$hostname_display" \
               --arg e "curl $curl_ec" \
            '{kind:"failed",href:$href,hostname:$hn,http:0,error:$e}' > "$result_path"
    elif [[ $http_code -ge 200 && $http_code -lt 300 ]]; then
        jq -nc --arg href "$workload_href" --arg hn "$hostname_display" \
               --argjson http "$http_code" \
            '{kind:"updated",dry_run:false,href:$href,hostname:$hn,http:$http}' > "$result_path"
    else
        jq -nc --arg href "$workload_href" --arg hn "$hostname_display" \
               --argjson http "$http_code" \
            '{kind:"failed",href:$href,hostname:$hn,http:$http,error:("PCE returned "+($http|tostring))}' \
            > "$result_path"
    fi
}

# --- 依賴檢查 ---
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
    echo >&2 "ERROR: bash >= 4.3 required (this script uses 'wait -n')."
    exit 1
fi
command -v curl >/dev/null 2>&1 || { echo >&2 "ERROR: required package 'curl' not installed. Please install it first."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo >&2 "ERROR: required package 'jq' not installed. Please install it first."; exit 1; }
command -v ipcalc >/dev/null 2>&1 || { echo >&2 "ERROR: required package 'ipcalc' not installed. Please install it first."; exit 1; }


# --- CLI argument parsing ---
VERSION="1.3.2"

require_arg() {
    if [[ $# -lt 2 || "$2" == --* ]]; then
        echo "ERROR: $1 requires a value" >&2; exit 5
    fi
}

# Defaults
SEARCH_TERMS_RAW=""
LABEL_ID=""
LABEL_KEY=""
LABEL_VALUE=""
UPDATE_MODE=""
NON_INTERACTIVE=0
DRY_RUN=0
JSON_OUT=0
CORRELATION_ID=""
REASON=""
AUDIT_FILE="${ILLUMIO_QUARANTINE_AUDIT_FILE:-}"
PARALLEL=1
CREDENTIALS_FILE=""
CLI_PCE_URL=""
CLI_ORG_ID=""
INSECURE=0

print_usage() {
    cat <<'USAGE'
Usage: illumio-quarantine.sh [OPTIONS]

Targets & action:
  --targets <csv>                     IP/hostname/CIDR/range/prefix (CSV)
  --label-id <id>                     Numeric Label ID
  --label-key <k> --label-value <v>   Look up label at runtime (mutually exclusive with --label-id)
  --mode append|overwrite             Default: append

Automation:
  --non-interactive                   Skip all prompts
  --dry-run                           No PUTs; still emit JSON + CEF
  --json                              Machine-readable JSON to stdout
  --correlation-id <id>               SIEM incident ID
  --reason <text>                     Incident/rule description
  --audit-file <path>                 Append CEF audit line (flock-protected)
  --parallel <n>                      Concurrent PUTs (1..20, default 1)
  --insecure                          Disable TLS cert verification (not recommended)

Overrides:
  --credentials-file <path>           key=value file with API_USER/API_PASS/[PCE_URL_BASE/ORG_ID]
  --pce-url <url>                     Override PCE base URL
  --org-id <id>                       Override Org ID

Meta:
  -h, --help                          Show this help
  -V, --version                       Print version

Env vars (after --credentials-file, before defaults):
  ILLUMIO_QUARANTINE_API_USER, ILLUMIO_QUARANTINE_API_PASS,
  ILLUMIO_QUARANTINE_PCE_URL,  ILLUMIO_QUARANTINE_ORG_ID,
  ILLUMIO_QUARANTINE_AUDIT_FILE

Exit codes:
  0 success | 2 partial | 3 no match | 4 auth fail / PCE unreachable or truncated | 5 input error | 6 no creds
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)          require_arg "$@"; SEARCH_TERMS_RAW="$2"; shift 2 ;;
        --label-id)         require_arg "$@"; LABEL_ID="$2";         shift 2 ;;
        --label-key)        require_arg "$@"; LABEL_KEY="$2";        shift 2 ;;
        --label-value)      require_arg "$@"; LABEL_VALUE="$2";      shift 2 ;;
        --mode)             require_arg "$@"; UPDATE_MODE="$2";      shift 2 ;;
        --non-interactive)  NON_INTERACTIVE=1;     shift ;;
        --dry-run)          DRY_RUN=1;             shift ;;
        --json)             JSON_OUT=1;            shift ;;
        --correlation-id)   require_arg "$@"; CORRELATION_ID="$2";   shift 2 ;;
        --reason)           require_arg "$@"; REASON="$2";           shift 2 ;;
        --audit-file)       require_arg "$@"; AUDIT_FILE="$2";       shift 2 ;;
        --parallel)         require_arg "$@"; PARALLEL="$2";         shift 2 ;;
        --insecure)         INSECURE=1;           shift ;;
        --credentials-file) require_arg "$@"; CREDENTIALS_FILE="$2"; shift 2 ;;
        --pce-url)          require_arg "$@"; CLI_PCE_URL="$2";      shift 2 ;;
        --org-id)           require_arg "$@"; CLI_ORG_ID="$2";       shift 2 ;;
        -h|--help)          print_usage; exit 0 ;;
        -V|--version)       echo "illumio-quarantine.sh $VERSION"; exit 0 ;;
        *)
            echo "ERROR: unknown option: $1" >&2
            print_usage >&2
            exit 5 ;;
    esac
done

# Non-TTY stdin → force non-interactive (prevents hanging in pipes/CI/SIEM)
[[ ! -t 0 && "$NON_INTERACTIVE" != "1" ]] && NON_INTERACTIVE=1

# Validate --parallel
if ! [[ "$PARALLEL" =~ ^[0-9]+$ ]] || [[ "$PARALLEL" -lt 1 || "$PARALLEL" -gt 20 ]]; then
    echo "ERROR: --parallel must be an integer in 1..20" >&2; exit 5
fi

if [[ "$INSECURE" == "1" ]]; then
    CURL_OPTS="${CURL_OPTS} -k"
fi

# Mutual exclusion / combinations for label target
if [[ -n "$LABEL_ID" && ( -n "$LABEL_KEY" || -n "$LABEL_VALUE" ) ]]; then
    echo "WARN: both --label-id and --label-key/--label-value given; --label-id takes precedence" >&2
    LABEL_KEY=""; LABEL_VALUE=""
fi

if [[ "$NON_INTERACTIVE" == "1" ]]; then
    [[ -z "$SEARCH_TERMS_RAW" ]] && { echo "ERROR: --targets required" >&2; exit 5; }
    if [[ -z "$LABEL_ID" ]]; then
        if [[ -z "$LABEL_KEY" || -z "$LABEL_VALUE" ]]; then
            echo "ERROR: --label-id or (--label-key and --label-value) required" >&2; exit 5
        fi
    fi
    if [[ -n "$LABEL_ID" ]] && ! [[ "$LABEL_ID" =~ ^[0-9]+$ ]]; then
        echo "ERROR: --label-id must be numeric" >&2; exit 5
    fi
    [[ -z "$UPDATE_MODE" ]] && UPDATE_MODE="append"
    if [[ "$UPDATE_MODE" != "append" && "$UPDATE_MODE" != "overwrite" ]]; then
        echo "ERROR: --mode must be append or overwrite" >&2; exit 5
    fi
fi

# --json is structured output; refuse the footgun of mixing with interactive mode
if [[ "$JSON_OUT" == "1" && "$NON_INTERACTIVE" != "1" ]]; then
    echo "ERROR: --json requires --non-interactive" >&2
    exit 5
fi

# Run-state accumulators for JSON emission — declared before any code path
# that can call emit_cef (which reads AUDIT_ID and the J_* arrays).
AUDIT_ID="qr-$(date -u +%Y-%m-%dT%H-%M-%SZ)-$(printf '%04x%02x' $((RANDOM)) $((RANDOM%256)))"
RUN_START_MS=$(date +%s%3N)
declare -a J_REQUESTED=()
declare -a J_MATCHED=()
declare -a J_UPDATED=()
declare -a J_SKIPPED=()
declare -a J_FAILED=()

hlog() { [[ "$JSON_OUT" != "1" ]] && echo "$@"; }

load_credentials
init_curl_auth_file


# Interactive prompts (skipped if --non-interactive)
if [[ "$NON_INTERACTIVE" != "1" ]]; then
    if [[ -z "$SEARCH_TERMS_RAW" ]]; then
        echo "Enter search terms (CSV of IP, hostname, CIDR, range, prefix):"
        read -e -p "Targets: " SEARCH_TERMS_RAW
    fi
    if [[ -z "$LABEL_ID" && ( -z "$LABEL_KEY" || -z "$LABEL_VALUE" ) ]]; then
        read -e -p "Label ID (numeric, or leave blank to use key/value): " LABEL_ID
        if [[ -z "$LABEL_ID" ]]; then
            read -e -p "Label key: "   LABEL_KEY
            read -e -p "Label value: " LABEL_VALUE
        fi
    fi
fi

# Post-prompt validation (applies in both modes)
[[ -z "$SEARCH_TERMS_RAW" ]] && { echo "ERROR: empty targets" >&2; exit 5; }
if [[ -z "$LABEL_ID" && ( -z "$LABEL_KEY" || -z "$LABEL_VALUE" ) ]]; then
    echo "ERROR: need --label-id or --label-key+--label-value" >&2; exit 5
fi
if [[ -n "$LABEL_ID" ]] && ! [[ "$LABEL_ID" =~ ^[0-9]+$ ]]; then
    echo "ERROR: label id must be numeric" >&2; exit 5
fi

resolve_target_label

if [[ "$JSON_OUT" != "1" ]]; then
    echo "illumio_Quarantine $VERSION"
    echo "label=${TARGET_LABEL_KEY}:${TARGET_LABEL_VALUE} (${TARGET_LABEL_HREF})"
    [[ -n "$CORRELATION_ID" ]] && echo "correlation_id=$CORRELATION_ID"
    [[ -n "$REASON"         ]] && echo "reason=$REASON"
fi

# --- 輸入解析 ---
IFS=',' read -ra SEARCH_TERMS <<< "$SEARCH_TERMS_RAW"
for i in "${!SEARCH_TERMS[@]}"; do
    # 清理每個搜索條件前後的空格
    SEARCH_TERMS[$i]=$(echo "${SEARCH_TERMS[$i]}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
done

# Seed J_REQUESTED from SEARCH_TERMS (raw, before normalization)
for t in "${SEARCH_TERMS[@]}"; do
    [[ -z "$t" ]] && continue
    J_REQUESTED+=("$(jq -nc --arg t "$t" '$t')")
done

# Reject malformed targets and normalize CIDR/range terms in place
validate_search_terms


# --- Step 1: Fetch workloads (server-side per-term if all precise, else one full scan) ---
WORKLOADS_BASE="${PCE_URL_BASE}/api/${API_VERSION}/orgs/${ORG_ID}/workloads"
SEARCH_STRATEGY=""

needs_full=0
for term in "${SEARCH_TERMS[@]}"; do
    [[ -z "$term" ]] && continue
    t=$(classify_term "$term")
    if [[ "$t" == "cidr" || "$t" == "range" || "$t" == "prefix" ]]; then
        needs_full=1; break
    fi
done

if [[ "$needs_full" == "1" ]]; then
    SEARCH_STRATEGY="full_scan"
    # Sync collection GETs are capped at PCE_SYNC_GET_MAX by the PCE anyway;
    # requesting more only hides the truncation.
    pce_get "${WORKLOADS_BASE}?max_results=${PCE_SYNC_GET_MAX}" "workloads full scan"
    api_response="$PCE_BODY"
else
    SEARCH_STRATEGY="server_side"
    api_response="[]"
    for term in "${SEARCH_TERMS[@]}"; do
        [[ -z "$term" ]] && continue
        t=$(classify_term "$term")
        enc_term=$(_urlenc "$term")
        if [[ "$t" == "ip" ]]; then
            pce_get "${WORKLOADS_BASE}?ip_address=${enc_term}" "workloads?ip_address=${term}"
        else
            pce_get "${WORKLOADS_BASE}?hostname=${enc_term}" "workloads?hostname=${term}"
        fi
        part="$PCE_BODY"
        if ! echo "$part" | jq -e 'type=="array"' >/dev/null 2>&1; then
            echo "ERROR: PCE returned non-array for term '${term}'" >&2; exit 4
        fi
        check_sync_truncation "$part" "term '${term}'"
        # Merge (dedup by href)
        api_response=$(jq -n --argjson a "$api_response" --argjson b "$part" \
            '$a + $b | unique_by(.href)')
    done
fi

# JSON validation (auth failures are already caught by status code in pce_get)
if ! echo "$api_response" | jq -e 'type=="array"' >/dev/null 2>&1; then
    echo "ERROR: PCE response is not a JSON array" >&2; emit_cef "failure"; exit 4
fi
if [[ "$SEARCH_STRATEGY" == "full_scan" ]]; then
    check_sync_truncation "$api_response" "workloads full scan"
fi


# --- 步驟 2: 過濾 Workloads ---
hlog
hlog "Analyzing matching workloads (managed: true only)..."
declare -A workloads_to_update # 存儲待更新 Workloads (鍵: href, 值: json{hostname, labels})
found_count=0                  # 唯一匹配的 Workload 計數

# 先用單次 jq 展平成 TSV（每個 managed Workload 一行:
# href、hostname、public_ip、空白分隔的介面 IP、labels JSON），
# 避免在外層循環中對每個 Workload 反覆呼叫 jq。
flat_workloads=$(echo "$api_response" | jq -r '
    .[]?
    | select(type == "object")
    | select((.href // "") != "")
    | select(.managed == true)
    | [ .href,
        (.hostname // "N/A"),
        (.public_ip // ""),
        ([.interfaces[]?.address | strings] | join(" ")),
        ([.labels[]? | {href}] | tostring) ]
    | @tsv')

# --- 外層循環: 遍歷 Workloads ---
while IFS=$'\t' read -r workload_href hostname public_ip addrs labels_json; do
    [[ -z "$workload_href" ]] && continue
    [[ -z "$labels_json" ]] && labels_json="[]"

    match_found_for_this_workload=false

    # --- 內層循環: 遍歷搜索條件 ---
    for term in "${SEARCH_TERMS[@]}"; do
        [[ -z "$term" ]] && continue
        term_matched_current_workload=false

        # 1. CIDR 匹配 (input 已由 validate_search_terms 正規化為網路位址)
        if [[ "$term" == */* ]]; then
            IFS='/' read -r input_network input_prefix <<< "$term"
            for cand in $public_ip $addrs; do
                calculated_network_output=$(ipcalc -n "${cand}/${input_prefix}" 2>/dev/null) || continue
                calculated_network=$(echo "$calculated_network_output" | grep -E '^(Network:|NETWORK=)' | head -n 1 | sed -E 's/^(Network:|NETWORK=)[[:space:]]*//; s|/.*||; s/[[:space:]]*$//')
                if [[ -n "$calculated_network" && "$calculated_network" == "$input_network" ]]; then
                    term_matched_current_workload=true; break
                fi
            done
        # 2./3. 範圍匹配 (- 或 ~)
        elif is_ipv4_range_dash "$term" || is_ipv4_range_tilde "$term"; then
            range_sep='-'
            [[ "$term" == *~* ]] && range_sep='~'
            IFS="$range_sep" read -r range_start range_end <<< "$term"
            for cand in $public_ip $addrs; do
                if is_in_range "$cand" "$range_start" "$range_end"; then
                    term_matched_current_workload=true; break
                fi
            done
        # 4. 其他 (主機名 / 精確 IP / 前綴)
        else
            if [[ "$hostname" == "$term" ]]; then
                term_matched_current_workload=true
            else
                is_prefix=false
                [[ "$term" == *. ]] && is_prefix=true
                for cand in $public_ip $addrs; do
                    if [[ "$cand" == "$term" ]]; then term_matched_current_workload=true; break; fi
                    if $is_prefix && [[ "$cand" == "$term"* ]]; then term_matched_current_workload=true; break; fi
                done
            fi
        fi # --- 結束條件匹配 ---

        # 如果當前條件匹配成功，跳出內層循環
        if $term_matched_current_workload; then
            match_found_for_this_workload=true
            break
        fi
    done # --- 結束內層循環 ---

    # 如果此 Workload 匹配了任何條件
    if $match_found_for_this_workload; then
        key=$(echo "$workload_href" | tr '/' '_') # 處理 href 作為 key
        value_json=$(jq -nc --arg hn "$hostname" --argjson lbls "$labels_json" '{hostname: $hn, labels: $lbls}')
        # 僅在首次匹配時打印消息和計數
        if [[ -z "${workloads_to_update[$key]}" ]]; then
            hlog "  -> match: ${hostname} (${workload_href})"
            J_MATCHED+=("$(jq -nc --arg h "$workload_href" --arg n "$hostname" \
                                  '{href:$h,hostname:$n}')")
            ((found_count++))
        fi
        workloads_to_update["$key"]="$value_json" # 存儲或更新信息
    fi
done <<< "$flat_workloads" # --- 結束外層循環 ---


# --- 步驟 3: 確認 ---
# 列出將受影響的 Workload 並請求用戶確認

# 檢查是否有匹配的 Workload
if [ ${#workloads_to_update[@]} -eq 0 ]; then
    hlog "No managed workload matched any target." >&2
fi

# 顯示將受影響的 Workload 列表
hlog
hlog "--------------------------------------------------"
hlog "${#workloads_to_update[@]} managed workloads will be affected:"
hlog "--------------------------------------------------"
for key in "${!workloads_to_update[@]}"; do
    workload_href=$(echo "$key" | tr '_' '/')
    stored_data_json="${workloads_to_update[$key]}"
    display_hostname=$(echo "$stored_data_json" | jq -r '.hostname // "N/A"')
    hlog "  - ${display_hostname} (${workload_href})"
done
hlog "--------------------------------------------------"

# 先選模式再確認：overwrite 具破壞性，用戶必須在按下 yes 前知道將用哪種模式
if [[ "$NON_INTERACTIVE" != "1" && -z "$UPDATE_MODE" && ${#workloads_to_update[@]} -gt 0 ]]; then
    echo "Label update mode:"
    echo "  1) append    (keep existing business labels; replace same-key)"
    echo "  2) overwrite (remove all existing labels; set only new)"
    read -e -p "Mode (1 or 2): " UPDATE_MODE_CHOICE
    case "$UPDATE_MODE_CHOICE" in
        1) UPDATE_MODE="append" ;;
        2) UPDATE_MODE="overwrite" ;;
        *) echo "ERROR: invalid mode choice" >&2; exit 5 ;;
    esac
fi
[[ -z "$UPDATE_MODE" ]] && UPDATE_MODE="append"

if [[ "$NON_INTERACTIVE" != "1" && ${#workloads_to_update[@]} -gt 0 ]]; then
    hlog "mode: ${UPDATE_MODE}"
    read -e -p "Continue? (type 'yes' to confirm): " CONFIRMATION
    if [[ "${CONFIRMATION,,}" != "yes" ]]; then
        hlog "Cancelled."
        exit 0
    fi
fi

hlog "--------------------------------------------------"


# --- 步驟 4: 執行更新 ---
# 遍歷確認要更新的 Workload 並發送 API 請求

hlog "Updating labels (parallel=${PARALLEL})..."
RESULT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/iq_results_XXXXXX") || {
    echo "ERROR: failed to create results temp dir" >&2; exit 1
}
active=0
for key in "${!workloads_to_update[@]}"; do
    workload_href=$(echo "$key" | tr '_' '/')
    stored_data_json="${workloads_to_update[$key]}"
    existing_labels_json=$(echo "$stored_data_json" | jq -c '.labels // []')
    hostname_display=$(echo "$stored_data_json" | jq -r '.hostname // "N/A"')

    put_one_workload "$workload_href" "$hostname_display" \
                     "$existing_labels_json" "$RESULT_DIR" &
    ((active++))
    if [[ $active -ge $PARALLEL ]]; then
        wait -n
        ((active--))
    fi
done
wait

# Aggregate per-workload result files into J_UPDATED / J_SKIPPED / J_FAILED
for f in "$RESULT_DIR"/*.json; do
    [[ -e "$f" ]] || continue
    kind=$(jq -r '.kind' "$f")
    case "$kind" in
        updated)
            entry=$(jq -c 'if .dry_run then {href,hostname,dry_run:true}
                           else {href,hostname} end' "$f")
            J_UPDATED+=("$entry")
            if [[ "$(jq -r '.dry_run // false' "$f")" == "true" ]]; then
                hlog "  -> DRY-RUN success ($(jq -r '.hostname' "$f"))"
            else
                hlog "  -> updated (HTTP $(jq -r '.http' "$f")) $(jq -r '.hostname' "$f")"
            fi
            ;;
        skipped)
            J_SKIPPED+=("$(jq -c '{href,hostname}' "$f")")
            hlog "  -> skipped (already labeled) $(jq -r '.hostname' "$f")"
            ;;
        failed)
            J_FAILED+=("$(jq -c '{href,hostname,http,error}' "$f")")
            echo "ERROR: PUT $(jq -r '.href' "$f") failed ($(jq -r '.error' "$f"))" >&2
            ;;
    esac
done
rm -rf "$RESULT_DIR"

hlog "--------------------------------------------------"

# --- Final JSON + exit-code ---
RUN_END_MS=$(date +%s%3N)
DURATION_MS=$((RUN_END_MS - RUN_START_MS))

ec=0
if   [[ ${#J_MATCHED[@]} -eq 0 ]]; then ec=3
elif [[ ${#J_FAILED[@]}  -gt 0 ]]; then ec=2
fi

# Promote partial → auth-failure exit 4 when EVERY PUT failed with 401/403.
if [[ $ec -eq 2 ]]; then
    auth_only=1
    for entry in "${J_FAILED[@]}"; do
        h=$(jq -r '.http // 0' <<<"$entry")
        if [[ "$h" != "401" && "$h" != "403" ]]; then
            auth_only=0
            break
        fi
    done
    # Also require there were no successes (J_UPDATED empty); otherwise it's
    # genuinely partial.
    if [[ "$auth_only" == "1" && ${#J_UPDATED[@]} -eq 0 && ${#J_SKIPPED[@]} -eq 0 ]]; then
        ec=4
    fi
fi

_arr() { local IFS=','; echo "[${*}]"; }

if [[ "$JSON_OUT" == "1" ]]; then
    jq -nc \
       --arg audit_id "$AUDIT_ID" \
       --arg correlation_id "$CORRELATION_ID" \
       --arg mode "$UPDATE_MODE" \
       --arg strategy "${SEARCH_STRATEGY:-full_scan}" \
       --argjson label "$(jq -nc --arg h "$TARGET_LABEL_HREF" \
                                  --arg k "$TARGET_LABEL_KEY" \
                                  --arg v "$TARGET_LABEL_VALUE" \
                                  '{href:$h,key:$k,value:$v}')" \
       --argjson requested "$(_arr "${J_REQUESTED[@]:-}")" \
       --argjson matched   "$(_arr "${J_MATCHED[@]:-}")" \
       --argjson updated   "$(_arr "${J_UPDATED[@]:-}")" \
       --argjson skipped   "$(_arr "${J_SKIPPED[@]:-}")" \
       --argjson failed    "$(_arr "${J_FAILED[@]:-}")" \
       --argjson parallel  "$PARALLEL" \
       --argjson dry_run   "$([[ $DRY_RUN == 1 ]] && echo true || echo false)" \
       --argjson duration  "$DURATION_MS" \
       --argjson exit_code "$ec" \
       '{audit_id:$audit_id, correlation_id:$correlation_id,
         mode:$mode, label:$label,
         requested_targets:$requested,
         search_strategy:$strategy,
         matched:$matched, updated:$updated,
         skipped_already_labeled:$skipped,
         failed:$failed,
         counts:{requested:($requested|length),
                 matched:($matched|length),
                 updated:($updated|length),
                 skipped:($skipped|length),
                 failed:($failed|length)},
         parallel:$parallel, dry_run:$dry_run,
         duration_ms:$duration, exit_code:$exit_code}'
fi
case "$ec" in
    0) outcome="success" ;;
    2) outcome="partial" ;;
    3) outcome="no_match" ;;
    *) outcome="failure" ;;
esac
emit_cef "$outcome"
exit "$ec"
