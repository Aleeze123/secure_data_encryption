import streamlit as st
import json, os, hashlib
from cryptography.fernet import Fernet
st.set_page_config(page_title="Secure Vault | Protect Your Secrets", page_icon="🔒")


st.markdown("""
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500&display=swap" rel="stylesheet">
    <style>
        html, body, .stApp {
            background-color: #0f1117;
            color: #f0f0f0;
            font-family: 'Orbitron', sans-serif;
        }
        .stTextInput > div > div > input,
        .stTextArea textarea {
            background-color: #1a1c23;
            color: #ffffff;
            border: 1px solid #00ffff;
        }
        .stButton button {
            background-color: #00ffff;
            color: #000000;
            font-weight: bold;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            transition: 0.3s ease-in-out;
        }
        .stButton button:hover {
            background-color: #00cccc;
            box-shadow: 0 0 10px #00ffff;
        }
        .stCodeBlock, pre {
            background-color: #1c1f2e !important;
            color: #00ffff !important;
            border: 1px solid #00ffff;
            padding: 10px;
        }
    </style>
""", unsafe_allow_html=True)

USERS_FILE = "users.json"
DATA_FILE = "data.json"
KEY_FILE = "secret.key"

def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

cipher = load_or_create_key()

def generate_salt():
    return os.urandom(16).hex()

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

def load_json(file):
    if not os.path.exists(file):
        return {}
    with open(file, "r") as f:
        return json.load(f)

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

users = load_json(USERS_FILE)
user_data = load_json(DATA_FILE)

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'page' not in st.session_state:
    st.session_state.page = "Login"

def login_page():
    st.title("🔐 Login to VaultX")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in users:
            user = users[username]
            hashed = hash_password(password, user['salt'])
            if hashed == user['password']:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.page = "Home"
                st.success("✅ Login successful!")
                return
        st.error("❌ Invalid username or password.")

def register_page():
    st.title("📝 Create Your VaultX Account")
    username = st.text_input("Choose Username")
    password = st.text_input("Create Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if username in users:
            st.warning("⚠ Username already taken.")
        elif not username or not password:
            st.warning("Please fill all fields.")
        elif password != confirm:
            st.error("❌ Passwords do not match.")
        else:
            salt = generate_salt()
            hashed = hash_password(password, salt)
            users[username] = {"password": hashed, "salt": salt}
            save_json(USERS_FILE, users)
            st.success("✅ Registration successful! Please login.")
            st.session_state.page = "Login"

def home_page():
    st.title("💾 VaultX | Secure Data Locker")
    st.markdown(f"Welcome, **`{st.session_state.username}`** 👋")
    st.markdown("<hr style='border: 1px solid #00ffff;'>", unsafe_allow_html=True)

    st.markdown("""
    VaultX is your personal encrypted data vault.  
    All secrets are encrypted locally with your custom passkey.  
    Use this tool to store or retrieve passwords, notes, or sensitive content securely.  
    """)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("🔒 Store Secret"):
            st.session_state.page = "Store"
    with col2:
        if st.button("🔍 Retrieve Secret"):
            st.session_state.page = "Retrieve"
    with col3:
        if st.button("🚪 Logout"):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.session_state.page = "Login"
            st.rerun()

def store_data():
    st.title("🔒 Store Secret")
    label = st.text_input("Label (e.g., 'Gmail Password')")
    secret = st.text_area("Enter Secret Data")
    passkey = st.text_input("Encryption Passkey", type="password")
    confirm = st.text_input("Confirm Passkey", type="password")

    if st.button("Encrypt & Store"):
        if passkey != confirm:
            st.error("❌ Passkeys do not match.")
        elif not secret or not label or not passkey:
            st.warning("Please fill all fields.")
        else:
            hashed_passkey = hash_password(passkey, passkey[:16])
            encrypted = cipher.encrypt(secret.encode()).decode()

            entry = {
                "label": label,
                "data": encrypted,
                "key": hashed_passkey
            }

            user_data.setdefault(st.session_state.username, []).append(entry)
            save_json(DATA_FILE, user_data)
            st.success("✅ Secret stored successfully!")

    if st.button("🔙 Back to Home"):
        st.session_state.page = "Home"

def retrieve_data():
    st.title("🔍 Retrieve Secret")
    entries = user_data.get(st.session_state.username, [])
    if not entries:
        st.info("No secrets stored yet.")
        if st.button("🔙 Back to Home"):
            st.session_state.page = "Home"
        return

    labels = [entry['label'] for entry in entries]
    selected = st.selectbox("Select Label", labels)
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        for entry in entries:
            if entry['label'] == selected:
                hashed_input = hash_password(passkey, passkey[:16])
                if hashed_input == entry['key']:
                    try:
                        decrypted = cipher.decrypt(entry['data'].encode()).decode()
                        st.success("✅ Decrypted Data:")
                        st.code(decrypted, language="text")
                        return
                    except:
                        st.error("⚠ Decryption failed.")
                        return
                else:
                    st.error("❌ Incorrect passkey.")
                    return

    if st.button("🔙 Back to Home"):
        st.session_state.page = "Home"

if not st.session_state.logged_in:
    if st.session_state.page == "Login":
        login_page()
        if st.button("Don't have an account? Register here"):
            st.session_state.page = "Register"
    elif st.session_state.page == "Register":
        register_page()
        if st.button("Already registered? Login here"):
            st.session_state.page = "Login"
else:
    if st.session_state.page == "Home":
        home_page()
    elif st.session_state.page == "Store":
        store_data()
    elif st.session_state.page == "Retrieve":
        retrieve_data()
