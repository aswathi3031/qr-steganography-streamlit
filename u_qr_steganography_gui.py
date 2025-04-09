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
import base64
import cv2
import joblib
import os
import random
import string

# Paths
private_key_path = "private.pem"
public_key_path = "public.pem"
password_path = "C:\\Users\\aswat\\Downloads\\qr_ics\\password.txt"
encrypted_message_path = "C:\\Users\\aswat\\Downloads\\qr_ics\\encrypted_message.txt"
qr_image_path = "encrypted_qr.png"
model_path = "qr_verification_model.pkl"

# Load ML model (currently unused but for future use)
model = joblib.load(model_path)

# Session state
if 'qr_verified' not in st.session_state:
    st.session_state.qr_verified = False
if 'encrypted_message_qr' not in st.session_state:
    st.session_state.encrypted_message_qr = None
if 'qr_password' not in st.session_state:
    st.session_state.qr_password = ""

# Utils
def generate_random_password(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def generate_keys():
    rsa_key = RSA.generate(2048)
    with open(private_key_path, "wb") as priv_file:
        priv_file.write(rsa_key.export_key())
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(rsa_key.publickey().export_key())

def encrypt_message(message):
    with open(public_key_path, "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

def generate_qr_code(message):
    st.session_state.encrypted_message_qr = encrypt_message(message)

    qr_url = "https://2dba-116-74-129-198.ngrok-free.app"  # Same link as tkinter
    with open(encrypted_message_path, "w") as msg_file:
        msg_file.write(message)

    qr = qrcode.make(qr_url)
    qr.save(qr_image_path)

    st.session_state.qr_password = generate_random_password()
    with open(password_path, "w") as pwd_file:
        pwd_file.write(st.session_state.qr_password)

def verify_uploaded_qr(uploaded_file):
    file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
    img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(img)
    if data and data == "https://2dba-116-74-129-198.ngrok-free.app":
        st.session_state.qr_verified = True
        return True
    return False

def decrypt_qr_message():
    if not st.session_state.qr_verified:
        return None

    with open(private_key_path, "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(base64.b64decode(st.session_state.encrypted_message_qr)).decode()
    return decrypted

# Layout
st.title("🔐 QR Code Encryption with RSA (Web Version)")

st.subheader("Sender Section")
if st.button("Generate RSA Keys"):
    generate_keys()
    st.success("Keys Generated Successfully.")

message = st.text_input("Enter Message to Encrypt")
if st.button("Encrypt Message & Generate QR Code"):
    if message:
        generate_qr_code(message)
        st.success("QR Code and Encrypted Message Generated Successfully.")
        st.image(qr_image_path, caption="Encrypted QR Code", width=200)
        st.info(f"🔗 QR URL: https://2dba-116-74-129-198.ngrok-free.app")
    else:
        st.warning("Please enter a message.")

# Display QR Password
if st.session_state.qr_password:
    st.info(f"🔒 Password: {st.session_state.qr_password}")

st.subheader("Receiver Section")

uploaded_file = st.file_uploader("Upload QR Code (PNG)", type=["png"])
if uploaded_file and st.button("Verify QR Code"):
    if verify_uploaded_qr(uploaded_file):
        st.success("✅ QR Code Verified Successfully!")
    else:
        st.error("QR Code Verification Failed. Possible Tampering Detected!")

if st.button("Decrypt Message"):
    if st.session_state.qr_verified and st.session_state.encrypted_message_qr:
        decrypted_msg = decrypt_qr_message()
        if decrypted_msg:
            st.success(f"🔓 Decrypted Message: {decrypted_msg}")
        else:
            st.warning("Decryption failed.")
    else:
        st.warning("QR Code must be verified before decryption.")
