import streamlit as st
import base64
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# GitHub secrets
GITHUB_TOKEN = st.secrets["GITHUB_TOKEN"]
REPO_NAME = st.secrets["REPO_NAME"]
USERNAME = st.secrets["USERNAME"]

def get_file(file_name):
    url = f"https://raw.githubusercontent.com/{REPO_NAME}/main/{file_name}"
    response = requests.get(url)
    return response.content.decode() if response.status_code == 200 else None

def decrypt_message(encrypted_b64, private_pem):
    private_key = RSA.import_key(private_pem.encode())
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_b64)).decode()
    return decrypted

st.title("📱 QR Decryption (Mobile Version)")

user_pwd = st.text_input("🔑 Enter Password", type="password")
if st.button("Verify & Decrypt"):
    stored_pwd = get_file("password.txt")
    if user_pwd == stored_pwd:
        st.success("✅ Password Correct!")
        encrypted = get_file("encrypted_message.txt")
        private_key = get_file("private.pem")
        decrypted = decrypt_message(encrypted, private_key)
        st.success(f"🔓 Decrypted Message: {decrypted}")
    else:
        st.error("❌ Incorrect Password!")
