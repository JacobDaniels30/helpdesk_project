import base64
import hashlib
import os

# Scrypt parameters
N = 2**14
r = 8
p = 1
dklen = 64


def generate_scrypt_hash(password):
    salt = os.urandom(16)
    key = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=N, r=r, p=p, dklen=dklen
    )
    hash_str = (
        f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"
    )
    return hash_str


# Define users
users = [
    {"email": "admin@example.com", "role": "admin", "password": "AdminPass123!"},
    {"email": "agent@example.com", "role": "agent", "password": "AgentPass123!"},
    {"email": "user@example.com", "role": "user", "password": "UserPass123!"},
]

# Generate SQL inserts
for u in users:
    hashed = generate_scrypt_hash(u["password"])
    print(
        f"INSERT INTO users (email, role, password_hash) VALUES ('{u['email']}', '{u['role']}', '{hashed}');\n"
    )
