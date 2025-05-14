import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import os

KEY_FILE = "fernet.key"

st.set_page_config(page_title="Secure Data App", layout="centered")


def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return key

KEY = load_or_create_key()
cipher = Fernet(KEY)


if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for value in st.session_state.stored_data.values():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None


menu = ["🏠 Home", "📂 Store Data", "🔍 Decrypt Data", "🔑 Login"]
choice = st.sidebar.radio("Choose Page", menu)


if choice.startswith("🏠"):
    st.title("🔒 Secure Data Encryption System")
    with st.expander("✨ What does this app do?"):
        st.markdown("""
        This app helps you:
        - 🔐 Encrypt and store sensitive data
        - 🧠 Protect it with a passkey
        - 🔓 Decrypt it only with the correct passkey
        - 🚫 Block access after 3 failed attempts
        """)
    st.success("Use the sidebar to store or retrieve encrypted data.")

elif choice.startswith("📂"):
    st.header("📂 Store Data Securely")
    st.markdown("Enter your data and a secret passkey to encrypt it.")

    with st.form("store_form"):
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")
        submit = st.form_submit_button("🔒 Encrypt & Save")

    if submit:
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)

            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }

            st.success("✅ Data encrypted and stored securely.")
            st.code(encrypted_text, language='text')
        else:
            st.error("⚠️ Both data and passkey are required.")


elif choice.startswith("🔍"):
    st.header("🔍 Retrieve Encrypted Data")

    if st.session_state.failed_attempts >= 3:
        st.warning("🔒 Too many failed attempts! Go to the **Login** page to reauthorize.")
        st.stop()

    with st.form("decrypt_form"):
        encrypted_input = st.text_area("Enter Encrypted Data:")
        passkey = st.text_input("Enter Passkey:", type="password")
        decrypt_btn = st.form_submit_button("🔓 Decrypt")

    if decrypt_btn:
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)

            if result:
                st.success("✅ Decryption successful!")
                st.text_area("Decrypted Data:", result, height=150)
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
        else:
            st.error("⚠️ Please enter both fields.")
            

elif choice.startswith("🔑"):
    st.header("🔑 Reauthorization Required")

    with st.form("login_form"):
        login_pass = st.text_input("Enter Master Password:", type="password")
        login_submit = st.form_submit_button("🔓 Login")

    if login_submit:
        if login_pass == "admin123":
            st.success("✅ Reauthorized successfully!")
            st.session_state.failed_attempts = 0
            st.info("Now you can return to the decrypt page.")
        else:
            st.error("❌ Incorrect master password.")
