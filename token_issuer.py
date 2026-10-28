import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE_DIR = Path(__file__).resolve().parent
PRIVATE_KEY_FILE = BASE_DIR / "issuer_private.pem"
PUBLIC_KEY_FILE = BASE_DIR / "issuer_public.pem"

ALGORITHM = "EdDSA"
ISSUER = "secure-edge-controller"


def load_or_create_keys():
    if PRIVATE_KEY_FILE.exists() and PUBLIC_KEY_FILE.exists():
        private_key = serialization.load_pem_private_key(
            PRIVATE_KEY_FILE.read_bytes(), password=None
        )
        public_key = serialization.load_pem_public_key(
            PUBLIC_KEY_FILE.read_bytes()
        )
        return private_key, public_key

    if PRIVATE_KEY_FILE.exists() or PUBLIC_KEY_FILE.exists():
        raise RuntimeError("Only one key file exists; inspect the files first.")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    PRIVATE_KEY_FILE.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    PUBLIC_KEY_FILE.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    PRIVATE_KEY_FILE.chmod(0o600)
    PUBLIC_KEY_FILE.chmod(0o644)

    return private_key, public_key


def issue_token(tenant_id, resources, lifetime_seconds=300):
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("tenant_id must be a non-empty string")

    if (
        not isinstance(resources, list)
        or not resources
        or any(not isinstance(r, str) or not r for r in resources)
        or len(set(resources)) != len(resources)
    ):
        raise ValueError("resources must be a non-empty list of unique strings")

    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 3600:
        raise ValueError("Lifetime must be between 1 and 3600 seconds")

    private_key, _ = load_or_create_keys()
    now = int(time.time())

    claims = {
        "iss": ISSUER,
        "sub": tenant_id,
        "tenant_id": tenant_id,
        "resources": resources,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime_seconds,
        "jti": str(uuid.uuid4()),
    }

    return jwt.encode(claims, private_key, algorithm=ALGORITHM)


if __name__ == "__main__":
    token = issue_token("tenant_A", ["resource_A"])
    print("Token issued successfully.")
    print("Tenant: tenant_A")
    print("Allowed resources: resource_A")
    print("Lifetime: 300 seconds")
    print("\nSigned token:\n")
    print(token)
