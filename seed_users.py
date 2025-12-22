from pymongo import MongoClient
import bcrypt
import getpass

# --- Configuration ---
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "users_db"

# --- Role Definitions ---
ROLE_MAKER = "MAKER"
ROLE_CHECKER = "CHECKER"
ROLE_ADMIN = "ADMIN"

def hash_password(password: str) -> str:
    """Hashes a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def get_collection_by_role(db, role):
    if role == ROLE_ADMIN:
        return db.admin_db
    elif role == ROLE_MAKER:
        return db.maker_db
    elif role == ROLE_CHECKER:
        return db.auth_db
    return None

def check_user_exists(db, username):
    """Checks if a username exists in any of the user collections."""
    if db.admin_db.find_one({"username": username}): return True
    if db.maker_db.find_one({"username": username}): return True
    if db.auth_db.find_one({"username": username}): return True
    return False

def create_user(db, role, username, full_name, email, password):
    """Reusable function to create a single user."""
    if check_user_exists(db, username):
        print(f"❌ User '{username}' already exists in the database.")
        return

    hashed_pw = hash_password(password)
    user_doc = {
        "username": username,
        "full_name": full_name,
        "email": email,
        "hashed_password": hashed_pw,
        "role": role,
        "disabled": False
    }
    
    collection = get_collection_by_role(db, role)
    collection.insert_one(user_doc)
    print(f"✅ Successfully created {role} user: {username}")

def interactive_user_creation():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]

    print("\n=== GTEE User Management System ===")
    print("This tool allows you to create users in the backend database without writing code.")
    
    while True:
        print("\nOptions:")
        print("1. Create New User")
        print("2. List All Users")
        print("3. Exit")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == '1':
            print("\n--- Create New User ---")
            print("Select Role Category:")
            print(f"1. {ROLE_ADMIN} (Back-end/System)")
            print(f"2. {ROLE_MAKER} (Creator)")
            print(f"3. {ROLE_CHECKER} (Authorizer)")
            
            role_choice = input("Enter role number: ").strip()
            role = None
            if role_choice == '1': role = ROLE_ADMIN
            elif role_choice == '2': role = ROLE_MAKER
            elif role_choice == '3': role = ROLE_CHECKER
            else:
                print("❌ Invalid role selection.")
                continue

            username = input("Username: ").strip()
            if not username:
                print("❌ Username cannot be empty.")
                continue
                
            full_name = input("Full Name: ").strip()
            email = input("Email: ").strip()
            password = getpass.getpass("Password: ")
            confirm_password = getpass.getpass("Confirm Password: ")
            
            if password != confirm_password:
                print("❌ Passwords do not match.")
                continue
            
            create_user(db, role, username, full_name, email, password)
            
        elif choice == '2':
            print("\n--- Existing Users ---")
            print(f"[{ROLE_ADMIN}S]")
            for u in db.admin_db.find(): print(f" - {u['username']} ({u.get('full_name', '')})")
            
            print(f"\n[{ROLE_MAKER}S]")
            for u in db.maker_db.find(): print(f" - {u['username']} ({u.get('full_name', '')})")
            
            print(f"\n[{ROLE_CHECKER}S]")
            for u in db.auth_db.find(): print(f" - {u['username']} ({u.get('full_name', '')})")
            
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

    client.close()

if __name__ == "__main__":
    interactive_user_creation()