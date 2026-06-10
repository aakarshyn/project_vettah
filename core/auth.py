import hashlib

# Mock Database. The password is 'cyberdome2026'
VALID_USERS = {
    "admin": "d821a7df362bb20d1c808799d5ba08c5ec3cf421458514ccb191c7a5ba0c4d28"
}

def verify_credentials(username, password):
    """Hashes provided password and checks against mock DB."""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return username in VALID_USERS and VALID_USERS[username] == password_hash