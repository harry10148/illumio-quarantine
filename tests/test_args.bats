#!/usr/bin/env bats
load 'helpers/setup.bash'
setup() { _load_libs; common_setup; }
teardown() { common_teardown; }

@test "--help prints usage and exits 0" {
    run bash "$SCRIPT" --help
    assert_success
    assert_output --partial "Usage:"
    assert_output --partial "--targets"
    assert_output --partial "--label-id"
    assert_output --partial "--label-key"
    assert_output --partial "--parallel"
    assert_output --partial "--insecure"
}

@test "--version prints 1.3.2" {
    run bash "$SCRIPT" --version
    assert_success
    assert_output --partial "1.3.2"
}

@test "non-interactive without --targets exits 5" {
    run bash "$SCRIPT" --label-id 878 --non-interactive --dry-run --json
    assert_failure 5
}

@test "non-interactive without any label id/key exits 5" {
    run bash "$SCRIPT" --targets 10.0.0.5 --non-interactive --dry-run --json
    assert_failure 5
}

@test "non-interactive with --label-key without --label-value exits 5" {
    run bash "$SCRIPT" --targets x --label-key Quarantine --non-interactive --dry-run --json
    assert_failure 5
}

@test "both --label-id and --label-key warns but accepts (id wins)" {
    run bash "$SCRIPT" --targets 10.0.0.5 --label-id 878 \
        --label-key Quarantine --label-value Severe \
        --non-interactive --dry-run --json
    assert_success
    assert_output --partial "--label-id takes precedence"
}

@test "unknown flag exits 5" {
    run bash "$SCRIPT" --nope --non-interactive
    assert_failure 5
    assert_output --partial "unknown option"
}

@test "--parallel must be 1..20" {
    run bash "$SCRIPT" --targets x --label-id 1 --parallel 0 --non-interactive --dry-run --json
    assert_failure 5
    run bash "$SCRIPT" --targets x --label-id 1 --parallel 21 --non-interactive --dry-run --json
    assert_failure 5
}

@test "non-interactive does not prompt for confirmation or mode" {
    run bash "$SCRIPT" --targets "10.0.0.5" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    assert_success
    refute_output --partial "Continue?"
}

@test "correlation-id and reason appear in header in human mode" {
    run bash "$SCRIPT" --targets "10.0.0.5" --label-id 878 \
        --non-interactive --dry-run \
        --correlation-id "INC-42" --reason "test rule"
    assert_success
    assert_output --partial "correlation_id=INC-42"
    assert_output --partial "reason=test rule"
}

@test "--json without --non-interactive succeeds in non-TTY (auto-promoted)" {
    # In non-TTY contexts (pipes, CI, SIEM), NON_INTERACTIVE is auto-set,
    # so --json alone is safe and succeeds.
    run bash "$SCRIPT" --targets "10.0.0.5" --label-id 878 --json
    assert_success
}

@test "value-taking flag without value exits 5" {
    run bash "$SCRIPT" --credentials-file --non-interactive
    assert_failure 5
    assert_output --partial "requires a value"
}

@test "non-TTY stdin without creds exits 6 instead of hanging" {
    unset ILLUMIO_QUARANTINE_API_USER
    unset ILLUMIO_QUARANTINE_API_PASS
    run bash "$SCRIPT" --targets foo --label-id 1 <<< ""
    assert_failure 6
}

@test "--insecure is accepted in non-interactive mode" {
    run bash "$SCRIPT" --targets "10.0.0.5" --label-id 878 \
        --non-interactive --dry-run --json --insecure
    assert_success
}
