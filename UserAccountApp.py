import hashlib
import os
import json
import uuid

USER_FILE = "users.json"
users = {}

# -----------------------------
# Role Hierarchy
# -----------------------------

class Role:
    def __init__(self, name, parent=None, permissions=None):
        self.name = name
        self.parent = parent
        self.permissions = permissions or set()

    def get_permissions(self):
        all_perms = set(self.permissions)
        if self.parent:
            all_perms |= self.parent.get_permissions()
        return all_perms
    
    def has_permission(self, permission):
        return permission in self.get_permissions()
    
    def __str__(self):
        return self.name
    
GUEST = Role("guest")
USER  = Role("user",  parent=GUEST, permissions={"view_own_profile"})
ADMIN = Role("admin", parent=USER,  permissions={"view_all_users", "manage_roles"})

ROLES = {
    "guest": GUEST,
    "user":  USER,
    "admin": ADMIN,
}

# -----------------------------
# Helper Functions
# -----------------------------

#changed protocol from salt to uuid system as a suggested change in the program from the lecture.

def generate_user_id():
    return str(uuid.uuid4())

def hash_with_id(password, user_id):
    return hashlib.sha256(user_id.encode() + password.encode()).hexdigest()

# -----------------------------
# File Operations
# -----------------------------

def load_users():
    global users

    if not os.path.exists(USER_FILE):
        print("No existing user file found. Starting fresh.")
        return
    with open(USER_FILE, "r") as f:
        data = json.load(f)
    for username, info in data.items():
        users[username] = {
            "user_id": info["user_id"],
            "hash":    info["hash"],
            "role":    info["role"]
        }
    print(f"Loaded {len(users)} user(s) from file.")

def save_users():
    data = {}

    for username, info in users.items():
        data[username] = {
            "user_id": info["user_id"],
            "hash":    info["hash"],
            "role":    info["role"]
        }

    with open(USER_FILE, "w") as f:
        json.dump(data, f, indent=4)
    print("User data saved to file.")

# -----------------------------
# Core Functionality
# -----------------------------

def register_user():
    username = input("Enter new username: ").strip()
    if username in users:
        print(f"User '{username}' already exists.")
        return
    password = input("Enter password: ").strip()

    valid_roles = [r for r in ROLES if r != "guest"]
    print(f"Available roles: {', '.join(valid_roles)}")
    role_name = input("Enter role: ").strip().lower()
    if role_name not in valid_roles:
        print("Invalid role. Defaulting to 'user'.")
        role_name = "user"

    user_id = generate_user_id()
    password_hash = hash_with_id(password, user_id)
    users[username] = {
        "user_id": user_id,
        "hash":    password_hash,
        "role":    role_name
    }

    role = ROLES[role_name]
    perms = role.get_permissions()
    print(f"User '{username}' registered as '{role}'.")
    print(f"Inherited permissions: {', '.join(perms) if perms else 'none'}")



def list_users(logged_in_user):
    if not users:
        print("No users registered.")
        return
    
    role = ROLES[users[logged_in_user]["role"]]

    if role.has_permission("view_all_users"):
        print("\n[ADMIN VIEW] All registered users:")
        for username, info in users.items():
            user_role = ROLES[info["role"]]
            perms = user_role.get_permissions()
            print(f"  {username}:")
            print(f"    user_id     : {info['user_id']}")
            print(f"    role        : {user_role}")
            print(f"    permissions : {', '.join(perms) if perms else 'none'}")

    elif role.has_permission("view_own_profile"):
        print("\n[USER VIEW] Your account info:")
        info = users[logged_in_user]
        user_role = ROLES[info["role"]]
        perms = user_role.get_permissions()
        print(f"  {logged_in_user}:")
        print(f"    user_id     : {info['user_id']}")
        print(f"    role        : {user_role}")
        print(f"    permissions : {', '.join(perms)}")

    else:
        print("Access denied.")

def validate_user():
    username = input("Enter username to validate: ").strip()
    password = input("Enter password to check: ").strip()

    if username not in users:
        print("Invalid Credentials!!!")
        return None
    
    user_id = users[username]["user_id"]
    stored_hash = users[username]["hash"]

    if hash_with_id(password, user_id) == stored_hash:
        role = ROLES[users[username]["role"]]
        perms = role.get_permissions()
        print(f"Login successful! Logged in as '{username}' ({role}).")
        print(f"Your permissions: {', '.join(perms) if perms else 'none'}")
        return username
    else:
        print("Invalid credentials!")
        return None

# -----------------------------
# Main Program Loop
# -----------------------------

def main():
    load_users()
    logged_in_user = None

    while True:
        print("\n--- Secure Auth System ---")
        if logged_in_user:
            role = ROLES[users[logged_in_user]["role"]]
            print(f"Logged in as: {logged_in_user} ({role})")

        print("1. Create a new user")
        print("2. List users")
        print("3. Login / Validate a user's password")
        if logged_in_user:
            print("4. Logout")
            print("5. Exit")
        else:
            print("4. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            register_user()

        elif choice == "2":
            if not logged_in_user:
                print("You must be logged in to view users.")
            else:
                list_users(logged_in_user)

        elif choice == "3":
            logged_in_user = validate_user()

        elif choice == "4":
            if logged_in_user:
                print(f"Logged out '{logged_in_user}'.")
                logged_in_user = None
            else:
                save_users()
                print("Exiting.")
                break
        elif choice == "5" and logged_in_user:
            save_users()
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
