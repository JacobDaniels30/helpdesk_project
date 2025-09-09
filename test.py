from flask_bcrypt import Bcrypt

from db import insert_user

# Initialize Bcrypt
bcrypt = Bcrypt()

# Define test user
password = "TestUser@123"  # Meets typical password rules
hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

test_user = {
    "name": "Test User",
    "email": "testuser@example.com",
    "password_hash": hashed_password,
    "role": "user",
    "is_verified": True,
}

# Insert user into Supabase
result = insert_user(test_user)
print("Inserted user:", result)
