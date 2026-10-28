from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_KEY_FILE = BASE_DIR / "issuer_public.pem"

ALGORITHM = "EdDSA"
ISSUER = "secure-edge-controller"
MAX_TOKEN_LIFETIME = 3600

RESOURCE_OWNERS = {
    "resource_A": "tenant_A",
    "resource_A2": "tenant_A",
    "resource_B": "tenant_B",
}

RESOURCE_STATES = {
    "resource_A": False,
    "resource_A2": False,
    "resource_B": False,
}


def load_public_key():
    if not PUBLIC_KEY_FILE.exists():
        raise FileNotFoundError(
            "Public key missing. Run token_issuer.py first."
        )

    return serialization.load_pem_public_key(
        PUBLIC_KEY_FILE.read_bytes()
    )


def verify_token(token):
    if not isinstance(token, str) or not token:
        raise jwt.InvalidTokenError("Token must be a non-empty string.")

    public_key = load_public_key()

    claims = jwt.decode(
        token,
        public_key,
        algorithms=[ALGORITHM],
        issuer=ISSUER,
        options={
            "require": [
                "iss", "sub", "tenant_id", "resources",
                "iat", "nbf", "exp", "jti"
            ]
        },
    )

    if not isinstance(claims, dict):
        raise jwt.InvalidTokenError("Token claims must be an object.")

    tenant_id = claims.get("tenant_id")
    subject = claims.get("sub")
    resources = claims.get("resources")
    token_id = claims.get("jti")

    if (
        not isinstance(tenant_id, str)
        or not tenant_id.strip()
        or not isinstance(subject, str)
        or not subject.strip()
    ):
        raise jwt.InvalidTokenError("Invalid tenant identity.")

    if subject != tenant_id:
        raise jwt.InvalidTokenError("Tenant identity mismatch.")

    if (
        not isinstance(resources, list)
        or not resources
        or any(
            not isinstance(resource, str) or not resource.strip()
            for resource in resources
        )
        or len(set(resources)) != len(resources)
    ):
        raise jwt.InvalidTokenError("Invalid resource permissions.")

    if (
        not isinstance(token_id, str)
        or not token_id.strip()
    ):
        raise jwt.InvalidTokenError("Invalid token identifier.")

    issued_at = claims.get("iat")
    not_before = claims.get("nbf")
    expires_at = claims.get("exp")

    if any(
        type(value) is not int
        for value in (issued_at, not_before, expires_at)
    ):
        raise jwt.InvalidTokenError("Invalid token time claims.")

    if not (
        issued_at <= not_before <= expires_at
        and expires_at > issued_at
        and expires_at - issued_at <= MAX_TOKEN_LIFETIME
    ):
        raise jwt.InvalidTokenError("Invalid token lifetime.")

    return claims


def control_resource(token, resource_id, action):
    try:
        claims = verify_token(token)
    except (jwt.InvalidTokenError, ValueError, OSError, TypeError) as exc:
        print(f"ACCESS DENIED: Invalid token ({exc})")
        return False

    tenant_id = claims["tenant_id"]

    if (
        not isinstance(resource_id, str)
        or resource_id not in RESOURCE_OWNERS
    ):
        print("ACCESS DENIED: Unknown resource.")
        return False

    if RESOURCE_OWNERS[resource_id] != tenant_id:
        print(f"ACCESS DENIED: {tenant_id} does not own {resource_id}.")
        return False

    if resource_id not in claims["resources"]:
        print(f"ACCESS DENIED: Token does not authorize {resource_id}.")
        return False

    if not isinstance(action, str) or action not in ("ON", "OFF"):
        print("ACCESS DENIED: Unsupported action.")
        return False

    RESOURCE_STATES[resource_id] = action == "ON"
    print(f"AUTHORIZED: {tenant_id} -> {resource_id}: {action}")
    return True


if __name__ == "__main__":
    print("Secure Multi-Tenant Edge Controller")
    print("Generating a token for Tenant A...")

    from token_issuer import issue_token

    token_a = issue_token("tenant_A", ["resource_A"])

    print("\nTest 1: Tenant A controls its own resource")
    control_resource(token_a, "resource_A", "ON")

    print("\nTest 2: Tenant A attempts to control Tenant B's resource")
    control_resource(token_a, "resource_B", "ON")

    print("\nFinal resource states:")
    for resource, state in RESOURCE_STATES.items():
        print(f"{resource}: {'ON' if state else 'OFF'}")
