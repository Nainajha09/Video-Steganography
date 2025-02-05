from flask import Flask, render_template_string, request, url_for
import socket
import cv2
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
from PIL import Image
import random
import threading
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import subprocess

app = Flask(__name__)
public_key = None  # Global variable to store the public key

# Ensure the static directory exists to store received video
if not os.path.exists('static/videos'):
    os.makedirs('static/videos')

# Function to verify the RSA signature
def verify_signature(signature, message, public_key):
    # Create a SHA-256 hash of the message
    hash_data = SHA256.new(message.encode())

    # Decode the signature from base64
    decoded_signature = base64.b64decode(signature)

    # Verify the signature
    try:
        pkcs1_15.new(public_key).verify(hash_data, decoded_signature)
        print("Signature is valid.")
        return True
    except (ValueError, TypeError):
        print("Signature verification failed.")
        return False

def extract_frame(video_path, frame_number):
    output_image_path = f"frame_{frame_number}.png"
    vidObj = cv2.VideoCapture(video_path)
    total_frames = int(vidObj.get(cv2.CAP_PROP_FRAME_COUNT))

    if frame_number >= total_frames:
        print(f"Frame number {frame_number} exceeds total frames ({total_frames})")
        return False

    vidObj.set(cv2.CAP_PROP_POS_FRAMES, frame_number)
    success, image = vidObj.read()
    if success:
        cv2.imwrite(output_image_path, image)
        print(f"Frame {frame_number} saved as {output_image_path}")
    vidObj.release()
    return success, output_image_path

def decode_image(image_path):
    image = Image.open(image_path)
    width, height = image.size

    data_bits = ""
    for x in range(width):
        for y in range(height):
            pixel = list(image.getpixel((x, y)))
            for i in range(3):  # RGB
                data_bits += str(pixel[i] & 1)

    data_bytes = [data_bits[i:i + 8] for i in range(0, len(data_bits), 8)]
    decoded_data = "".join([chr(int(byte, 2)) for byte in data_bytes])
    delimiter_index = decoded_data.find("###")
    return decoded_data[:delimiter_index] if delimiter_index != -1 else None

def decrypt_message(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message[AES.block_size:]), AES.block_size)
    return decrypted_message.decode('utf-8')

def start_client():
    global public_key
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    # First Diffie-Hellman for Key Frame
    alice_public1 = int(client_socket.recv(1024).decode())
    bob_private1 = random.randint(1, 23 - 1)
    bob_public1 = pow(5, bob_private1, 23)
    client_socket.sendall(f"{bob_public1}".encode())
    shared_secret1 = pow(alice_public1, bob_private1, 23)
    print(f"Shared Secret for Key Frame: {shared_secret1}")

    # Second Diffie-Hellman for Message Frame
    alice_public2 = int(client_socket.recv(1024).decode())
    bob_private2 = random.randint(1, 23 - 1)
    bob_public2 = pow(5, bob_private2, 23)
    client_socket.sendall(f"{bob_public2}".encode())
    shared_secret2 = pow(alice_public2, bob_private2, 23)
    print(f"Shared Secret for Message Frame: {shared_secret2}")

    # Receive Public Key
    public_key_data = client_socket.recv(4096).decode()
    if public_key_data.startswith("PUBLIC_KEY:"):
        encoded_public_key = public_key_data.split("PUBLIC_KEY:")[1]
        public_key = RSA.import_key(base64.b64decode(encoded_public_key))
        print("Public key received and imported.")

    # Receive Video File
    output_video_path = 'static/videos/received_video.avi'
    with open(output_video_path, 'wb') as f:
        while True:
            video_data = client_socket.recv(4096)
            if not video_data:
                break
            f.write(video_data)
    client_socket.close()
    print("Video and public key received successfully.")

    return shared_secret1, shared_secret2, output_video_path

def convert_avi_to_mp4(input_path, output_path):
    command = [
        'ffmpeg', '-i', input_path, '-vcodec', 'libx264', '-acodec', 'aac', output_path
    ]
    subprocess.run(command, check=True)

def decrypt_video(shared_secret1, shared_secret2, video_path):
    global public_key
    # Decode AES Key from Key Frame
    key_frame_number = shared_secret1
    success, key_frame_image_path = extract_frame(video_path, key_frame_number)
    if not success:
        raise Exception(f"Failed to extract key frame {key_frame_number}")
    encoded_key = decode_image(key_frame_image_path)
    aes_key = base64.b64decode(encoded_key.encode('utf-8'))

    # Decode Encrypted Message from Message Frame
    message_frame_number = shared_secret2
    success, message_frame_image_path = extract_frame(video_path, message_frame_number)
    if not success:
        raise Exception(f"Failed to extract message frame {message_frame_number}")
    encoded_message = decode_image(message_frame_image_path)

    # Decode Signature from Signature Frame
    signature_frame_number = 0
    success, signature_frame_path = extract_frame(video_path, signature_frame_number)
    if not success:
        raise Exception(f"Failed to extract signature frame {signature_frame_number}")
    signature = decode_image(signature_frame_path)

    # Decrypt the message using the decoded AES key
    decrypted_message = decrypt_message(encoded_message, aes_key)
    print(f"Decrypted message: {decrypted_message}")

    # Verify the signature
    is_valid_signature = verify_signature(signature, decrypted_message, public_key)
    print("Signature valid:", is_valid_signature)

    # Convert AVI to MP4
    mp4_video_path = 'static/videos/received_video.mp4'
    convert_avi_to_mp4(video_path, mp4_video_path)

    return decrypted_message, is_valid_signature, mp4_video_path

@app.route('/', methods=['GET', 'POST'])
def index():
    global public_key
    message = ""
    video_url = None
    if request.method == 'POST':
        action = request.form['action']
        if action == 'connect':
            try:
                shared_secret1, shared_secret2, video_path = start_client()
                message = f"Connected to server. Shared secrets: {shared_secret1}, {shared_secret2}"
                video_url = None
            except Exception as e:
                message = f"Error connecting to server: {str(e)}"
        elif action == 'decrypt':
            try:
                shared_secret1 = int(request.form['shared_secret1'])
                shared_secret2 = int(request.form['shared_secret2'])
                video_path = 'static/videos/received_video.avi'
                decrypted_message, is_valid_signature, mp4_video_path = decrypt_video(shared_secret1, shared_secret2, video_path)
                message = f"Decrypted message: {decrypted_message} \n Signature valid: {is_valid_signature}"
                video_url = url_for('static', filename='videos/received_video.mp4') if is_valid_signature else None
            except Exception as e:
                message = f"Error decrypting video: {str(e)}"

    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>Secure Video Decryption</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/animejs/3.2.1/anime.min.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: 'Share Tech Mono', monospace;
            }

            body {
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                background: url('https://hebbkx1anhila5yf.public.blob.vercel-storage.com/background1.jpg-GniHpJfnZfhznNLEUmdNl9kQIfYLyi.jpeg') no-repeat center center fixed;
                background-size: cover;
                padding: 20px;
                color: #fff;
            }

            .container {
                width: 100%;
                max-width: 500px;
                background: rgba(0, 0, 0, 0.8);
                padding: 2rem;
                border-radius: 15px;
                box-shadow: 0 0 30px rgba(0, 157, 255, 0.3);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(0, 157, 255, 0.1);
                opacity: 0;
                transform: translateY(20px);
            }

            h1 {
                color: #00d8ff;
                text-align: center;
                margin-bottom: 2rem;
                font-size: 2rem;
                text-shadow: 0 0 10px rgba(0, 157, 255, 0.5);
            }

            form {
                display: flex;
                flex-direction: column;
                gap: 1rem;
                margin-bottom: 1.5rem;
                opacity: 0;
                transform: translateY(20px);
            }

            input {
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(0, 157, 255, 0.2);
                padding: 12px;
                border-radius: 8px;
                color: #fff;
                font-size: 1rem;
                transition: all 0.3s ease;
            }

            input:focus {
                outline: none;
                border-color: #00d8ff;
                box-shadow: 0 0 15px rgba(0, 157, 255, 0.3);
            }

            input[type="submit"] {
                background: linear-gradient(45deg, #006c9e, #00d8ff);
                color: #000;
                font-weight: bold;
                cursor: pointer;
                border: none;
                text-transform: uppercase;
                letter-spacing: 2px;
            }

            input[type="submit"]:hover {
                transform: scale(1.02);
                box-shadow: 0 0 20px rgba(0, 157, 255, 0.4);
            }

            .message {
                margin-top: 1.5rem;
                padding: 1.5rem;
                background: rgba(0, 157, 255, 0.1);
                border-left: 4px solid #00d8ff;
                border-radius: 8px;
                opacity: 0;
                transform: translateX(-20px);
            }

            video {
                width: 100%;
                margin-top: 1.5rem;
                border-radius: 8px;
                box-shadow: 0 0 20px rgba(0, 157, 255, 0.3);
                display: none;
            }

            @keyframes pulse {
                0% { box-shadow: 0 0 0 0 rgba(0, 157, 255, 0.4); }
                70% { box-shadow: 0 0 0 10px rgba(0, 157, 255, 0); }
                100% { box-shadow: 0 0 0 0 rgba(0, 157, 255, 0); }
            }

            .pulse {
                animation: pulse 2s infinite;
            }

            .cyber-line {
                position: absolute;
                height: 2px;
                background: linear-gradient(90deg, transparent, #00d8ff, transparent);
                width: 100%;
                left: 0;
                animation: scan 3s linear infinite;
            }

            @keyframes scan {
                0% { top: 0; opacity: 0; }
                5% { opacity: 1; }
                95% { opacity: 1; }
                100% { top: 100%; opacity: 0; }
            }
        </style>
    </head>
    <body>
        <div class="cyber-line"></div>
        <div class="container">
            <h1>SECURE VIDEO DECRYPTION</h1>
            <form method="post" class="connect-form">
                <input type="hidden" name="action" value="connect">
                <input type="submit" value="Connect to Server" class="pulse">
            </form>
            <form method="post" class="decrypt-form">
                <input type="hidden" name="action" value="decrypt">
                <input type="number" name="shared_secret1" placeholder="Enter Shared Secret 1" required>
                <input type="number" name="shared_secret2" placeholder="Enter Shared Secret 2" required>
                <input type="submit" value="Decrypt Video">
            </form>
            {% if message %}
            <div class="message">
                {{ message }}
            </div>
            {% endif %}
            {% if video_url %}
            <video controls>
                <source src="{{ video_url }}" type="video/mp4">
                Your browser does not support the video tag.
            </video>
            <script>
                document.addEventListener('DOMContentLoaded', function() {
                    document.querySelector('video').style.display = 'block';
                });
            </script>
            {% endif %}
        </div>

        <script>
            document.addEventListener('DOMContentLoaded', function() {
                // Initial animations
                anime({
                    targets: '.container',
                    opacity: [0, 1],
                    translateY: [20, 0],
                    duration: 1000,
                    easing: 'easeOutExpo'
                });

                anime({
                    targets: 'form',
                    opacity: [0, 1],
                    translateY: [20, 0],
                    delay: anime.stagger(200),
                    duration: 800,
                    easing: 'easeOutExpo'
                });

                if (document.querySelector('.message')) {
                    anime({
                        targets: '.message',
                        opacity: [0, 1],
                        translateX: [-20, 0],
                        duration: 800,
                        delay: 400,
                        easing: 'easeOutExpo'
                    });
                }

                // Add hover animations to submit buttons
                document.querySelectorAll('input[type="submit"]').forEach(button => {
                    button.addEventListener('mouseover', () => {
                        anime({
                            targets: button,
                            scale: 1.02,
                            duration: 200,
                            easing: 'easeOutExpo'
                        });
                    });

                    button.addEventListener('mouseout', () => {
                        anime({
                            targets: button,
                            scale: 1,
                            duration: 200,
                            easing: 'easeOutExpo'
                        });
                    });
                });
            });
        </script>
    </body>
    </html>
    ''', message=message, video_url=video_url)

if __name__ == '__main__':
    app.run(debug=True, port=5001)

