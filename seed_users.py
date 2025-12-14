from pymongo import MongoClient
from passlib.context import CryptContext

# --- Configuration ---
# This should match the settings in your main.py
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "gtee_db"
USER_COLLECTION = "users"

# --- User Data ---
# Add as many users as you need to this list
users_to_create = [
    {"username": "user1", "full_name": "Test User One", "email": "user1@example.com", "password": "password123"},
    {"username": "user2", "full_name": "Test User Two", "email": "user2@example.com", "password": "password456"},
    {"username": "manager", "full_name": "Manager Account", "email": "manager@example.com", "password": "securepassword"},
    # Add more user dictionaries here
]

def seed_bulk_users():
    """Connects to MongoDB, hashes passwords, and inserts multiple users."""
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[USER_COLLECTION]
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    print(f"Connecting to MongoDB and preparing to seed {len(users_to_create)} users...")

    for user_data in users_to_create:
        # Check if user already exists
        if collection.find_one({"username": user_data["username"]}):
            print(f"User '{user_data['username']}' already exists. Skipping.")
            continue

        # Hash the password and prepare the document for insertion
        hashed_password = pwd_context.hash(user_data.pop("password"))
        user_document = {**user_data, "hashed_password": hashed_password, "disabled": False}
        collection.insert_one(user_document)
        print(f"Successfully created user: '{user_data['username']}'")

    client.close()
    print("Seeding process complete.")

if __name__ == "__main__":
    seed_bulk_users()