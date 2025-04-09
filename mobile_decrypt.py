# mobile_decrypt.py
import streamlit as st
import base64
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# GitHub secrets
GITHUB_TOKEN = st.secrets["GITHUB_TOKEN"]
REPO_NAME = st.secrets["REPO_NAME"]
USERNAME = st.secrets["USERNAME"]

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

def get_file(file_name):
    url = f"https://raw.githubusercontent.com/{USERNAME}/{REPO_NAME}/main/{file_name}"
    response = requests.get(url, headers=HEADERS)
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
    if stored_pwd and user_pwd == stored_pwd:
        st.success("✅ Password Correct!")
        encrypted = get_file("encrypted_message.txt")
        private_key = get_file("private.pem")
        if encrypted and private_key:
            decrypted = decrypt_message(encrypted, private_key)
            st.success(f"🔓 Decrypted Message: {decrypted}")
        else:
            st.error("❌ Failed to fetch encrypted data.")
    else:
        st.error("❌ Incorrect Password!")
