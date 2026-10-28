import time

from token_issuer import issue_token
from edge_controller import control_resource, RESOURCE_STATES


passed = 0
failed = 0


def check(name, condition):
    global passed, failed

    if condition:
        passed += 1
        print(f"PASS: {name}")
    else:
        failed += 1
        print(f"FAIL: {name}")


def reset_resources():
    for resource in RESOURCE_STATES:
        RESOURCE_STATES[resource] = False


def main():
    print("\n=== SECURE EDGE CONTROLLER: SECURITY TESTS ===\n")
    reset_resources()

    # Test 1: Valid token can control an authorized resource.
    token_a = issue_token("tenant_A", ["resource_A"])
    result = control_resource(token_a, "resource_A", "ON")
    check(
        "Valid token permits authorized access",
        result is True and RESOURCE_STATES["resource_A"] is True,
    )

    # Test 2: Tenant A cannot control Tenant B's resource.
    token_a = issue_token("tenant_A", ["resource_A"])
    result = control_resource(token_a, "resource_B", "ON")
    check(
        "Cross-tenant access is blocked",
        result is False and RESOURCE_STATES["resource_B"] is False,
    )

    # Test 3: Tenant A owns resource_A2, but its token
    # does not grant permission to control it.
    limited_token = issue_token("tenant_A", ["resource_A"])
    result = control_resource(limited_token, "resource_A2", "ON")
    check(
        "Missing token permission is rejected",
        result is False and RESOURCE_STATES["resource_A2"] is False,
    )

    # Test 4: Modified token signature must be rejected.
    valid_token = issue_token("tenant_A", ["resource_A"])
    tampered_token = valid_token[:-1] + (
        "A" if valid_token[-1] != "A" else "B"
    )
    result = control_resource(tampered_token, "resource_A", "ON")
    check(
        "Tampered token is rejected",
        result is False,
    )

    # Test 5: Expired tokens must be rejected.
    expired_token = issue_token(
        "tenant_A", ["resource_A"], lifetime_seconds=1
    )
    time.sleep(2)
    result = control_resource(expired_token, "resource_A", "ON")
    check(
        "Expired token is rejected",
        result is False,
    )

    # Test 6: Tenant B can control its own resource.
    token_b = issue_token("tenant_B", ["resource_B"])
    result = control_resource(token_b, "resource_B", "ON")
    check(
        "Tenant B can control its authorized resource",
        result is True and RESOURCE_STATES["resource_B"] is True,
    )

    # Test 7: Tenant B cannot control Tenant A's resource.
    token_b = issue_token("tenant_B", ["resource_B"])
    result = control_resource(token_b, "resource_A", "ON")
    check(
        "Tenant B cannot control Tenant A's resource",
        result is False,
    )

        # Test 8: Unsupported actions must not change resource state.
    token_a = issue_token("tenant_A", ["resource_A"])
    previous_state = RESOURCE_STATES["resource_A"]
    result = control_resource(token_a, "resource_A", "DELETE")
    check(
        "Unsupported action is rejected without changing state",
        result is False
        and RESOURCE_STATES["resource_A"] is previous_state,
    )

    # Test 9: Unknown resource IDs must be rejected.
    previous_states = RESOURCE_STATES.copy()
    result = control_resource(token_a, "resource_UNKNOWN", "ON")
    check(
        "Unknown resource is rejected",
        result is False and RESOURCE_STATES == previous_states,
    )

    # Test 10: Empty tokens must be rejected safely.
    previous_states = RESOURCE_STATES.copy()
    result = control_resource("", "resource_A", "ON")
    check(
        "Empty token is rejected without changing state",
        result is False and RESOURCE_STATES == previous_states,
    )

    # Test 11: Non-string tokens must be rejected safely.
    previous_states = RESOURCE_STATES.copy()
    result = control_resource(None, "resource_A", "ON")
    check(
        "Non-string token is rejected without changing state",
        result is False and RESOURCE_STATES == previous_states,
    )
    print("\n--- FINAL RESOURCE STATES ---")
    for resource, state in sorted(RESOURCE_STATES.items()):
        print(f"{resource}: {'ON' if state else 'OFF'}")

    print("\n--- TEST SUMMARY ---")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total:  {passed + failed}")

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
