import streamlit as st
import hashlib
import base64
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

# Initialize session state for persistent storage
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"

# Generate or load Fernet key (in production, store securely)
if 'fernet_key' not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
cipher = Fernet(st.session_state.fernet_key)

# JSON file for data persistence
DATA_FILE = "encrypted_data.json"

# Function to save data to JSON
def save_to_json():
    with open(DATA_FILE, 'w') as f:
        json.dump(st.session_state.stored_data, f)

# Function to load data from JSON
def load_from_json():
    try:
        with open(DATA_FILE, 'r') as f:
            st.session_state.stored_data = json.load(f)
    except FileNotFoundError:
        st.session_state.stored_data = {}

# Load data on startup
load_from_json()

# Function to hash passkey using PBKDF2HMAC
def hash_passkey(passkey):
    salt = secrets.token_bytes(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return salt.hex() + ':' + key.decode()

# Function to verify passkey
def verify_passkey(passkey, stored_hash):
    try:
        salt_hex, stored_key = stored_hash.split(':')
        salt = bytes.fromhex(salt_hex)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passkey.encode())).decode()
        return key == stored_key
    except:
        return False

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    try:
        for key, value in st.session_state.stored_data.items():
            if key == encrypted_text and verify_passkey(passkey, value["passkey"]):
                st.session_state.failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()
        st.session_state.failed_attempts += 1
        return None
    except:
        st.session_state.failed_attempts += 1
        return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))

# Redirect to Login page after 3 failed attempts
if st.session_state.failed_attempts >= 3 and choice != "Login":
    st.session_state.current_page = "Login"
    st.experimental_rerun()

if choice == "Home":
    st.session_state.current_page = "Home"
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.write("Navigate using the sidebar to store or retrieve your data.")

elif choice == "Store Data":
    st.session_state.current_page = "Store Data"
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:", key="store_data")
    passkey = st.text_input("Enter Passkey:", type="password", key="store_passkey")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            save_to_json()  # Persist to JSON
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.session_state.current_page = "Retrieve Data"
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:", key="retrieve_data")
    passkey = st.text_input("Enter Passkey:", type="password", key="retrieve_passkey")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page...")
                    st.session_state.current_page = "Login"
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.session_state.current_page = "Login"
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password", key="login_pass")

    if st.button("Login"):
        # Hardcoded for demo; in production, use proper auth
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.current_page = "Retrieve Data"
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")