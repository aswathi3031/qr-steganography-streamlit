from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

encrypted_message_path = "C:\\Users\\aswat\\Downloads\\qr_ics\\encrypted_message.txt"
password_path = "C:\\Users\\aswat\\Downloads\\qr_ics\\password.txt"

# Load the password from the file
def load_password():
    try:
        with open(password_path, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None

# Load the encrypted message
def load_encrypted_message():
    try:
        with open(encrypted_message_path, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "Error: Encrypted message not found!"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/verify", methods=["POST"])
def verify():
    entered_password = request.form.get("password")
    stored_password = load_password()
    
    if entered_password == stored_password:
        return redirect(url_for("message"))
    else:
        return "Incorrect Password! Please try again.", 401

@app.route("/message")
def message():
    decrypted_message = load_encrypted_message() 
    return render_template("message.html", message=decrypted_message)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)

