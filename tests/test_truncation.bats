#!/usr/bin/env bats
# The PCE silently truncates synchronous collection GETs at 500 results.
# A quarantine run on truncated data could miss targets, so the script must
# refuse to continue when a collection response hits the cap.
load 'helpers/setup.bash'
setup() { _load_libs; common_setup; }
teardown() { common_teardown; }

@test "full scan returning 500 workloads fails hard (exit 4, truncation warning)" {
    export MOCK_CURL_WL_COUNT=500
    run bash "$SCRIPT" --targets "10.99.0.0/16" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    [[ "$status" -eq 4 ]]
    run echo "$output"
    assert_output --partial "truncated"
    assert_output --partial "respond-async"
}

@test "full scan under the cap proceeds normally" {
    export MOCK_CURL_WL_COUNT=120
    run bash "$SCRIPT" --targets "10.99.0.0/16" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    assert_success
    [[ "$(echo "$output" | jq -r '.counts.matched')" == "120" ]]
}

@test "labels?key= returning 500 labels fails hard (exit 4)" {
    export MOCK_CURL_LABELS_COUNT=500
    run bash "$SCRIPT" --targets "10.0.0.5" --label-key "Quarantine" --label-value "v1" \
        --mode append --non-interactive --dry-run --json
    [[ "$status" -eq 4 ]]
    run echo "$output"
    assert_output --partial "truncated"
}

@test "full scan requests max_results=500 (sync cap), not an inflated number" {
    run bash "$SCRIPT" --targets "10.0.0.0/24" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    assert_success
    run grep -c "workloads?max_results=500" "$MOCK_CURL_LOG"
    refute_output "0"
}
