from token_issuer import issue_token
from edge_controller import control_resource, RESOURCE_STATES

print("\n=== SECURE MULTI-TENANT EDGE CONTROLLER ===")

# Issue separate tokens for two tenants.
token_a = issue_token("tenant_A", ["resource_A"])
token_b = issue_token("tenant_B", ["resource_B"])

print("\n--- Tenant A ---")
control_resource(token_a, "resource_A", "ON")
control_resource(token_a, "resource_B", "ON")

print("\n--- Tenant B ---")
control_resource(token_b, "resource_B", "ON")
control_resource(token_b, "resource_A", "ON")

print("\n--- Final Resource States ---")
for resource, state in sorted(RESOURCE_STATES.items()):
    print(f"{resource}: {'ON' if state else 'OFF'}")

print("\n=== DEMONSTRATION COMPLETE ===")
