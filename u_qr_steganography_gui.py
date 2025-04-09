# import customtkinter as ctk 
# import tkinter as tk
# from tkinter import filedialog, messagebox
# import qrcode
# from PIL import Image, ImageTk
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# from Crypto.Signature import DSS
# from Crypto.Hash import SHA256
# import base64
# from pyzbar.pyzbar import decode
# import joblib
# import os
# import random
# import string


# private_key_path = "private.pem"
# public_key_path = "public.pem"
# sign_key_path = "sign_private.pem"
# sign_pub_key_path = "sign_public.pem"
# password_path = "C:\\Users\\aswat\\Downloads\\qr_ics\\password.txt"
# keys_generated = False  
# encrypted_message_qr = None  
# qr_verified = False  
# qr_image = None  
# qr_password = ""  

# # Load ML model
# model_path = "qr_verification_model.pkl"
# model = joblib.load(model_path)

# def generate_random_password(length=8):
#     characters = string.ascii_letters + string.digits
#     return ''.join(random.choice(characters) for _ in range(length))

# def generate_keys():
#     global keys_generated
#     rsa_key = RSA.generate(2048)

    
#     with open(private_key_path, "wb") as priv_file:
#         priv_file.write(rsa_key.export_key())
#     with open(public_key_path, "wb") as pub_file:
#         pub_file.write(rsa_key.publickey().export_key())

#     keys_generated = True
#     messagebox.showinfo("Success", " Keys Generated Successfully!")

# def encrypt_message(message):
#     with open(public_key_path, "rb") as pub_file:
#         public_key = RSA.import_key(pub_file.read())
#     cipher = PKCS1_OAEP.new(public_key)
#     encrypted = cipher.encrypt(message.encode())
#     return base64.b64encode(encrypted).decode()

# def generate_qr():
#     global encrypted_message_qr, qr_image, qr_password
#     message = message_entry.get()
#     if not message:
#         messagebox.showwarning("Warning", "Enter a message to encrypt!")
#         return

#     encrypted_message_qr = encrypt_message(message)
#     qr_url = "https://3d45-103-86-182-226.ngrok-free.app"

#     encrypted_message_path = "C:\\Users\\aswat\\Downloads\\qr_ics\\encrypted_message.txt"
#     with open(encrypted_message_path, "w") as msg_file:
#         msg_file.write(message)  

#     qr = qrcode.make(qr_url)
#     qr.save("encrypted_qr.png")
    
#     qr_password = generate_random_password()
#     with open(password_path, "w") as pwd_file:
#         pwd_file.write(qr_password)
    
#     img = Image.open("encrypted_qr.png").resize((200, 200))
#     qr_image = ImageTk.PhotoImage(img)
#     qr_label.configure(image=qr_image)
#     qr_label.image = qr_image
    
#     encrypted_display.configure(state="normal")
#     encrypted_display.delete("0.0", "end")
#     encrypted_display.insert("0.0", f"🔗 QR Code URL: {qr_url}")  
#     encrypted_display.configure(state="disabled")
    
#     messagebox.showinfo("Success", "QR Code Generated Successfully!")

# def verify_qr():
#     global qr_verified
#     file_path = filedialog.askopenfilename(title="Select QR Code", filetypes=[("PNG Files", "*.png")])
#     if not file_path:
#         return
    
#     qr = Image.open(file_path)
#     decoded_data = decode(qr)
    
#     if decoded_data:
#         scanned_message = decoded_data[0].data.decode()
#         if scanned_message == "https://3d45-103-86-182-226.ngrok-free.app":
#             qr_verified = True
#             messagebox.showinfo("Verified", "✅ QR Code is Verified!")
            
            
#             password_label.configure(state="normal")
#             password_label.delete("0.0", "end")
#             password_label.insert("0.0", f"🔒 Password: {qr_password}")
#             password_label.configure(state="disabled")
#             return
    
#     messagebox.showerror("Error", " QR Code is Tampered!\n Man in the middle attack is possible")

# def decrypt_qr_message():
#     if not qr_verified:
#         messagebox.showerror("Error", " QR is not verified! Decryption not allowed.")
#         return
    
#     with open(private_key_path, "rb") as priv_file:
#         private_key = RSA.import_key(priv_file.read())
#     cipher = PKCS1_OAEP.new(private_key)
#     decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message_qr)).decode()
    
#     result_display.configure(state="normal")
#     result_display.delete("0.0", "end")
#     result_display.insert("0.0", f"🔓{decrypted_message}")
#     result_display.configure(state="disabled")

# # GUI Setup
# ctk.set_appearance_mode("Light")
# ctk.set_default_color_theme("blue")

# root = ctk.CTk()
# root.title("QR Code Encryption with RSA")
# root.geometry("400x700")

# frame = ctk.CTkFrame(root, border_width=1, border_color="black")
# frame.pack(pady=10, padx=20, fill="both", expand=True)

# title_label = ctk.CTkLabel(frame, text="🔐 QR Code Verification", font=("Arial", 22, "bold"), text_color="black")
# title_label.pack(pady=10)


# sender_frame = ctk.CTkFrame(frame, fg_color="#ADD8E6", border_width=1, border_color="black")  
# sender_frame.pack(pady=10, padx=10, fill="both")

# rsa_btn = ctk.CTkButton(sender_frame, text=" Generate Keys", fg_color="blue", width=300, height=30, border_width=1, border_color="black", command=generate_keys)
# rsa_btn.pack(pady=10)

# message_entry = ctk.CTkEntry(sender_frame, width=300, height=30, border_width=1, border_color="black")
# message_entry.pack(pady=5)

# qr_btn = ctk.CTkButton(sender_frame, text=" Encrypt & Generate QR", fg_color="blue", width=300, height=30, border_width=1, border_color="black", command=generate_qr)
# qr_btn.pack(pady=10)

# encrypted_display = ctk.CTkTextbox(sender_frame, width=300, height=45, state="disabled", border_width=1, border_color="black")
# encrypted_display.pack(pady=5)

# qr_label = ctk.CTkLabel(sender_frame, text="QR Code Preview", width=300, height=30, fg_color="lightgray")  
# qr_label.pack(pady=10)


# receiver_frame = ctk.CTkFrame(frame, fg_color="#FAFAD2", border_width=1, border_color="black")  
# receiver_frame.pack(pady=10, padx=10, fill="both")

# verify_btn = ctk.CTkButton(receiver_frame, text=" Upload QR for Verification", fg_color="#B8860B", width=300, height=30, border_width=1, border_color="black", command=verify_qr)
# verify_btn.pack(pady=10)


# password_label = ctk.CTkTextbox(receiver_frame, width=300, height=30, state="disabled", border_width=1, border_color="black")
# password_label.pack(pady=5)

# decrypt_btn = ctk.CTkButton(receiver_frame, text=" Decrypt Message",  fg_color="#B8860B", width=300, height=30, border_width=1, border_color="black", command=decrypt_qr_message)
# decrypt_btn.pack(pady=10)


# result_display = ctk.CTkTextbox(receiver_frame, width=300, height=30, state="disabled", border_width=1, border_color="black")
# result_display.pack(pady=10)

# exit_btn = ctk.CTkButton(frame, text="Exit", fg_color="red", width=300, height=30, border_width=1, border_color="black", command=root.quit)
# exit_btn.pack(pady=10)

# root.mainloop()


import streamlit as st
import qrcode
from PIL import Image
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64, os, random, string, requests

# GitHub secrets
GITHUB_TOKEN = st.secrets["GITHUB_TOKEN"]
REPO_NAME = st.secrets["REPO_NAME"]
USERNAME = st.secrets["USERNAME"]
BRANCH = "main"

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# Session state setup
st.session_state.setdefault("qr_verified", False)
st.session_state.setdefault("encrypted_message_qr", None)
st.session_state.setdefault("qr_password", "")
st.session_state.setdefault("private_key", None)
st.session_state.setdefault("public_key", None)

def get_paths():
    return {
        "private_key": "private.pem",
        "public_key": "public.pem",
        "password": "password.txt",
        "message": "encrypted_message.txt",
        "qr": "encrypted_qr.png"
    }

def upload_to_github(filename, content_bytes):
    url = f"https://api.github.com/repos/{USERNAME}/{REPO_NAME}/contents/{filename}"
    get_response = requests.get(url, headers=HEADERS)
    sha = get_response.json().get("sha") if get_response.status_code == 200 else None

    payload = {
        "message": f"Update {filename}",
        "content": base64.b64encode(content_bytes).decode(),
        "branch": BRANCH
    }
    if sha:
        payload["sha"] = sha

    res = requests.put(url, headers=HEADERS, json=payload)
    return res.status_code in [200, 201]

def generate_random_password(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_keys():
    rsa_key = RSA.generate(2048)
    private_bytes = rsa_key.export_key()
    public_bytes = rsa_key.publickey().export_key()

    st.session_state["private_key"] = private_bytes
    st.session_state["public_key"] = public_bytes

    success1 = upload_to_github(get_paths()["private_key"], private_bytes)
    success2 = upload_to_github(get_paths()["public_key"], public_bytes)

    if success1 and success2:
        st.success("✅ RSA keys generated and uploaded to GitHub.")
    else:
        st.error("❌ Failed to upload RSA keys to GitHub.")

def encrypt_message(message):
    pub_key = RSA.import_key(st.session_state["public_key"])
    cipher = PKCS1_OAEP.new(pub_key)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

def generate_qr_code(message):
    encrypted = encrypt_message(message)
    st.session_state.encrypted_message_qr = encrypted

    upload_msg = upload_to_github(get_paths()["message"], encrypted.encode())

    # ✅ Save QR to local directory
    qr = qrcode.make(encrypted)
    qr_save_dir = r"C:\Users\aswat\Downloads\qr_ics"
    os.makedirs(qr_save_dir, exist_ok=True)
    qr_path = os.path.join(qr_save_dir, "encrypted_qr.png")
    qr.save(qr_path)

    # Upload QR to GitHub
    with open(qr_path, "rb") as qr_file:
        qr_data = qr_file.read()
        upload_qr = upload_to_github(get_paths()["qr"], qr_data)

    # Generate and upload password
    password = generate_random_password()
    st.session_state.qr_password = password
    upload_pwd = upload_to_github(get_paths()["password"], password.encode())

    if upload_msg and upload_qr and upload_pwd:
        st.success("✅ Encrypted QR & Password Generated.")
        st.image(qr_path)
    else:
        st.error("❌ Failed to upload encrypted data to GitHub.")

def verify_uploaded_qr(uploaded_file):
    uploaded_bytes = uploaded_file.read()
    stored_qr = requests.get(
        f"https://raw.githubusercontent.com/{USERNAME}/{REPO_NAME}/main/{get_paths()['qr']}"
    ).content
    if uploaded_bytes == stored_qr:
        st.session_state.qr_verified = True
        return True
    st.session_state.qr_verified = False
    return False

def decrypt_qr_message():
    priv_url = f"https://raw.githubusercontent.com/{USERNAME}/{REPO_NAME}/main/{get_paths()['private_key']}"
    private_key = RSA.import_key(requests.get(priv_url).content)
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(base64.b64decode(st.session_state.encrypted_message_qr)).decode()

# -------------------------- UI ----------------------------

st.title("🔐 QR Code Steganography (Sender Interface)")

st.subheader("Sender Section")
if st.button("Generate RSA Keys"):
    generate_keys()

message = st.text_input("Enter Message to Encrypt")
if st.button("Encrypt Message & Generate QR Code"):
    if not st.session_state["public_key"]:
        st.warning("⚠️ Please generate RSA keys first.")
    elif message:
        generate_qr_code(message)
    else:
        st.warning("⚠️ Please enter a message to encrypt.")

st.subheader("Receiver Section")
uploaded_file = st.file_uploader("📤 Upload QR Code (PNG)", type=["png"])
if uploaded_file and st.button("Verify QR Code"):
    if verify_uploaded_qr(uploaded_file):
        st.success("✅ QR Code Verified.")
        st.info(f"🔐 Password: {st.session_state.qr_password}")
    else:
        st.error("❌ QR Code Verification Failed!")

if st.button("Decrypt Message"):
    if st.session_state.qr_verified:
        st.success(f"🔓 Message: {decrypt_qr_message()}")
    else:
        st.warning("⚠️ Please verify QR first.")
