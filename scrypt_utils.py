import base64
import hashlib
import secrets


def generate_scrypt_hash(password: str, salt: bytes = None) -> str:
    """
    Generate a scrypt hash for the given password.

    Args:
        password: The password to hash
        salt: Optional salt bytes. If None, a random salt will be generated

    Returns:
        A string containing the scrypt hash in format: scrypt$salt$hash
    """
    if salt is None:
        salt = secrets.token_bytes(32)

    # scrypt parameters: password, salt, N, r, p, dklen
    # N=2^14, r=8, p=1 are reasonable defaults
    hash_bytes = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64
    )

    # Format: scrypt$salt_base64$hash_base64
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(hash_bytes).decode("ascii")

    return f"scrypt${salt_b64}${hash_b64}"


def verify_scrypt_hash(password: str, stored_hash: str) -> bool:
    """
    Verify a password against a stored scrypt hash.

    Args:
        password: The password to verify
        stored_hash: The stored scrypt hash string

    Returns:
        True if password matches, False otherwise
    """
    try:
        # Parse the stored hash format: scrypt$salt$hash
        parts = stored_hash.split("$")
        if len(parts) != 3 or parts[0] != "scrypt":
            return False

        salt_b64 = parts[1]
        hash_b64 = parts[2]

        # Decode base64
        salt = base64.b64decode(salt_b64)
        expected_hash = base64.b64decode(hash_b64)

        # Generate hash with same parameters
        computed_hash = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64
        )

        # Constant-time comparison
        return secrets.compare_digest(expected_hash, computed_hash)

    except Exception:
        return False


def is_scrypt_hash(hash_str: str) -> bool:
    """Check if the given string is a scrypt hash."""
    return hash_str.startswith("scrypt$") and len(hash_str.split("$")) == 3


def is_bcrypt_hash(hash_str: str) -> bool:
    """Check if the given string is a bcrypt hash."""
    return hash_str.startswith("$2") and len(hash_str) >= 50
