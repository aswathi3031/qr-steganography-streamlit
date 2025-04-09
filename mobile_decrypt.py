import streamlit as st
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

SHARED_PATH = "/tmp/shared"

def get_file(file_name):
    path = os.path.join(SHARED_PATH, file_name)
    return open(path).read() if os.path.exists(path) else None

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
