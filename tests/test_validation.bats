#!/usr/bin/env bats
# Input-validation regressions: a quarantine run must never silently ignore
# a malformed target term.
load 'helpers/setup.bash'
setup() { _load_libs; common_setup; }
teardown() { common_teardown; }

@test "invalid CIDR prefix /33 exits 5" {
    run bash "$SCRIPT" --targets "10.0.0.0/33" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    [[ "$status" -eq 5 ]]
    run echo "$output"
    assert_output --partial "invalid CIDR"
}

@test "invalid CIDR network 999.0.0.0/24 exits 5" {
    run bash "$SCRIPT" --targets "999.0.0.0/24" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    [[ "$status" -eq 5 ]]
}

@test "invalid IPv4 999.1.2.3 exits 5" {
    run bash "$SCRIPT" --targets "999.1.2.3" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    [[ "$status" -eq 5 ]]
    run echo "$output"
    assert_output --partial "invalid IPv4"
}

@test "IP range with start > end exits 5" {
    run bash "$SCRIPT" --targets "10.0.0.6-10.0.0.5" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    [[ "$status" -eq 5 ]]
    run echo "$output"
    assert_output --partial "start > end"
}

@test "digits-and-dots garbage '10.0.0' exits 5 instead of matching nothing" {
    run bash "$SCRIPT" --targets "10.0.0" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    [[ "$status" -eq 5 ]]
}

@test "non-numeric prefix term 'web01.' exits 5" {
    run bash "$SCRIPT" --targets "web01." --label-id 878 \
        --mode append --non-interactive --dry-run --json
    [[ "$status" -eq 5 ]]
    run echo "$output"
    assert_output --partial "invalid IP-prefix"
}

@test "one invalid term among valid ones still exits 5 (no partial silent run)" {
    run bash "$SCRIPT" --targets "10.0.0.5,10.0.0.0/33" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    [[ "$status" -eq 5 ]]
}

@test "CIDR host address is normalized to its network (10.0.0.5/24 matches the /24)" {
    run bash "$SCRIPT" --targets "10.0.0.5/24" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    assert_success
    [[ "$(echo "$output" | jq -r '.counts.matched')" == "2" ]]
}

@test "IP range tolerates spaces around the dash" {
    run bash "$SCRIPT" --targets "10.0.0.5 - 10.0.0.6" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    assert_success
    [[ "$(echo "$output" | jq -r '.counts.matched')" == "2" ]]
}

@test "leading-zero octets parse as decimal, not octal" {
    run bash "$SCRIPT" --targets "10.0.0.05-10.0.0.06" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    assert_success
    refute_output --partial "value too great"
    [[ "$(echo "$output" | jq -r '.counts.matched')" == "2" ]]
}

@test "valid prefix term still matches (regression)" {
    run bash "$SCRIPT" --targets "10.0.0." --label-id 878 \
        --mode append --non-interactive --dry-run --json
    assert_success
    [[ "$(echo "$output" | jq -r '.counts.matched')" == "2" ]]
}
