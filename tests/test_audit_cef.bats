#!/usr/bin/env bats
load 'helpers/setup.bash'
setup() { _load_libs; common_setup; }
teardown() { common_teardown; }

@test "audit file created with CEF header" {
    local f="$BATS_TMPDIR_LOCAL/a.cef"
    run bash "$SCRIPT" --targets "10.0.0.5" --label-id 878 \
        --mode append --non-interactive --dry-run --json \
        --correlation-id "INC-A" --reason "bats" --audit-file "$f"
    assert_success
    run cat "$f"
    assert_output --partial "CEF:0|Illumio|Quarantine|1.3.2|quarantine.action"
    assert_output --partial "cs1=INC-A"
    assert_output --partial "cs3=bats"
    assert_output --partial "cs5=Quarantine"
    assert_output --partial "cs6=Severe"
    assert_output --partial "flexString1=true"
}

@test "escaping of | and = in reason" {
    local f="$BATS_TMPDIR_LOCAL/a.cef"
    run bash "$SCRIPT" --targets "10.0.0.5" --label-id 878 \
        --mode append --non-interactive --dry-run --json \
        --reason "rule|a=b" --audit-file "$f"
    run cat "$f"
    assert_output --partial 'cs3=rule\|a\=b'
}

@test "outcome=no_match when nothing matches" {
    local f="$BATS_TMPDIR_LOCAL/a.cef"
    run bash "$SCRIPT" --targets "192.0.2.99" --label-id 878 \
        --mode append --non-interactive --dry-run --json --audit-file "$f"
    [[ "$status" -eq 3 ]]
    run cat "$f"
    assert_output --partial "outcome=no_match"
}

@test "flock prevents interleaving of concurrent writers" {
    local f="$BATS_TMPDIR_LOCAL/a.cef"
    for i in $(seq 1 10); do
        bash "$SCRIPT" --targets "10.0.0.5" --label-id 878 \
            --mode append --non-interactive --dry-run --json \
            --reason "run-$i" --audit-file "$f" >/dev/null &
    done
    wait
    run awk '!/^CEF:0\|/{print "BAD:" $0}' "$f"
    assert_output ""
    run wc -l < "$f"
    assert_output "10"
}

@test "no audit file when --audit-file omitted" {
    run bash "$SCRIPT" --targets "10.0.0.5" --label-id 878 \
        --mode append --non-interactive --dry-run --json
    assert_success
}

@test "space escaping prevents CEF injection via correlation-id" {
    local f="$BATS_TMPDIR_LOCAL/a.cef"
    run bash "$SCRIPT" --targets "10.0.0.5" --label-id 878 \
        --mode append --non-interactive --dry-run --json \
        --correlation-id "INC1 outcome=fake" --audit-file "$f"
    assert_success
    run cat "$f"
    # Verify space is escaped (INC1\ outcome\=fake) and no unescaped outcome=fake token
    assert_output --partial 'cs1=INC1\ outcome\=fake'
    # Ensure the injection attempt (unescaped "outcome=fake") is NOT present as a separate field
    refute_output --regexp 'outcome=fake[^\\]'
}

@test "refuse to write audit file when AUDIT_FILE is a symlink" {
    local f="$BATS_TMPDIR_LOCAL/audit.cef"
    local target="$BATS_TMPDIR_LOCAL/attack_target"
    # Create a target file that should NOT be written to
    touch "$target"
    # Create symlink at audit file location pointing to target
    ln -s "$target" "$f"

    run bash "$SCRIPT" --targets "10.0.0.5" --label-id 878 \
        --mode append --non-interactive --dry-run --json \
        --audit-file "$f" 2>&1

    # Should still complete (exit 0 or 3 depending on match)
    # But stderr must contain the warning
    assert_output --partial "WARNING: refusing to write audit"
    assert_output --partial "is a symbolic link"

    # Verify target file was not written to (should still be empty)
    run cat "$target"
    assert_output ""
}

@test "refuse to write audit lock when AUDIT_FILE.lock is a symlink" {
    local f="$BATS_TMPDIR_LOCAL/audit.cef"
    local lock_target="$BATS_TMPDIR_LOCAL/attack_lock_target"
    # Create target file that should NOT be written to
    touch "$lock_target"
    # Create symlink at lock location pointing to target
    ln -s "$lock_target" "${f}.lock"
    # Create the audit file itself (not a symlink)
    touch "$f"

    run bash "$SCRIPT" --targets "10.0.0.5" --label-id 878 \
        --mode append --non-interactive --dry-run --json \
        --audit-file "$f" 2>&1

    # Should still complete but stderr must contain warning
    assert_output --partial "WARNING: refusing to use audit lock"
    assert_output --partial "is a symbolic link"

    # Verify lock target was not written to (should still be empty)
    run cat "$lock_target"
    assert_output ""
}
