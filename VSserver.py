from flask import Flask, request, render_template_string
import socket
import cv2
import os
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64
import random
import threading

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


app = Flask(__name__)

shared_secrets = {'secret1': None, 'secret2': None}
processing_complete = False
server_socket = None

# Step 1: Generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Step 2: Sign a custom message
def create_signature(message, private_key):
    hash_data = SHA256.new(message.encode())
    rsa_key = RSA.import_key(private_key)
    signature = pkcs1_15.new(rsa_key).sign(hash_data)
    return base64.b64encode(signature).decode('utf-8')


def get_video_properties(video_path):
    vidObj = cv2.VideoCapture(video_path)
    fps = vidObj.get(cv2.CAP_PROP_FPS)
    frame_count = int(vidObj.get(cv2.CAP_PROP_FRAME_COUNT))
    width = int(vidObj.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(vidObj.get(cv2.CAP_PROP_FRAME_HEIGHT))
    vidObj.release()
    return fps, frame_count, (width, height)


def extract_frames(video_path, output_folder):
    vidObj = cv2.VideoCapture(video_path)
    count = 0
    success, image = vidObj.read()

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    while success:
        frame_path = os.path.join(output_folder, f"frame{count}.png")
        cv2.imwrite(frame_path, image)
        count += 1
        success, image = vidObj.read()

    vidObj.release()
    print(f"Total {count} frames extracted and saved as PNG.")
    return count


def frames_to_video(frame_folder, output_video_path, fps, frame_count, resolution):
    img_array = []
    for count in range(frame_count):
        frame_path = os.path.join(frame_folder, f"frame{count}.png")
        img = cv2.imread(frame_path)
        img_array.append(img)

    out = cv2.VideoWriter(output_video_path, cv2.VideoWriter_fourcc(*'FFV1'), fps, resolution)

    for img in img_array:
        out.write(img)

    out.release()
    print(f"Video saved as {output_video_path}")


def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_message).decode('utf-8')


def encode_image(image_path, data, output_path):
    image = Image.open(image_path)
    encoded_image = image.copy()

    width, height = image.size
    data += "###"  # Delimiter to indicate the end
    data_bits = "".join([format(ord(char), '08b') for char in data])

    bit_index = 0
    for x in range(width):
        for y in range(height):
            pixel = list(encoded_image.getpixel((x, y)))
            for i in range(3):  # RGB
                if bit_index < len(data_bits):
                    pixel[i] = pixel[i] & ~1 | int(data_bits[bit_index])
                    bit_index += 1
            encoded_image.putpixel((x, y), tuple(pixel))
            if bit_index >= len(data_bits):
                break
        if bit_index >= len(data_bits):
            break

    encoded_image.save(output_path)
    print(f"Data encoded and saved in {output_path}")


def diffie_hellman_exchange():
    prime = 23  
    base = 5
    private_key = random.randint(2, prime - 1)
    public_key = pow(base, private_key, prime)
    return private_key, public_key, prime, base


def start_server(video_path, message):
    global shared_secrets, processing_complete, server_socket

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Server waiting for connection...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # First Diffie-Hellman for Key Frame
    private_key1, public_key1, prime, base = diffie_hellman_exchange()
    conn.sendall(f"{public_key1}".encode())
    bob_public1 = int(conn.recv(1024).decode())
    shared_secret1 = pow(bob_public1, private_key1, prime)
    shared_secrets['secret1'] = shared_secret1
    print(f"Shared Secret for Key Frame: {shared_secret1}")

    # Second Diffie-Hellman for Message Frame
    private_key2, public_key2, _, _ = diffie_hellman_exchange()
    conn.sendall(f"{public_key2}".encode())
    bob_public2 = int(conn.recv(1024).decode())
    shared_secret2 = pow(bob_public2, private_key2, prime)
    shared_secrets['secret2'] = shared_secret2
    print(f"Shared Secret for Message Frame: {shared_secret2}")

    # Ensure Key Frame and Message Frame are not the same
    if shared_secret1 == shared_secret2:
        shared_secret2 += 1
        shared_secrets['secret2'] = shared_secret2
        print(f"Adjusted Shared Secret for Message Frame: {shared_secret2}")

    # Generate AES Key and Encrypt Message
    aes_key = get_random_bytes(16)
    encrypted_message = encrypt_message(message, aes_key)
    print(f"Encrypted message: {encrypted_message}")

    # Convert AES Key to Base64 String
    encoded_key = base64.b64encode(aes_key).decode('utf-8')

    # Extract Frames and Encode Data
    frame_folder = "video_frames"
    frame_count = extract_frames(video_path, frame_folder)

    key_frame_number = shared_secret1 % frame_count
    message_frame_number = shared_secret2 % frame_count

    private_key, public_key = generate_rsa_keys()
    signature = create_signature(message, private_key)

    encode_image(os.path.join(frame_folder, f"frame{key_frame_number}.png"), encoded_key,
                 os.path.join(frame_folder, f"frame{key_frame_number}.png"))
    encode_image(os.path.join(frame_folder, f"frame{message_frame_number}.png"), encrypted_message,
                 os.path.join(frame_folder, f"frame{message_frame_number}.png"))
    
    encode_image(os.path.join(frame_folder, f"frame{0}.png"), signature, os.path.join(frame_folder, f"frame{0}.png"))

    # Convert Frames Back to Video
    output_video_path = "output_video.avi"
    fps, _, resolution = get_video_properties(video_path)
    frames_to_video(frame_folder, output_video_path, fps, frame_count, resolution)

    # Send Video to Client
    encoded_public_key = base64.b64encode(public_key).decode('utf-8')

    # Send the public key to the client
    conn.sendall(f"PUBLIC_KEY:{encoded_public_key}".encode())

    # Introduce a small delay to avoid overlapping data
    import time
    time.sleep(1)

    # Send video data
    with open(output_video_path, 'rb') as f:
        video_data = f.read()
        conn.sendall(video_data)

    conn.close()
    print("Public key and video sent successfully.")

    conn.close()
    server_socket.close()
    print("Video sent successfully.")
    processing_complete = True


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    global shared_secrets, processing_complete, server_socket
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        message = request.form['message']
        if file.filename == '':
            return 'No selected file'
        if file and message:
            video_path = os.path.join('uploads', file.filename)
            file.save(video_path)
            shared_secrets = {'secret1': None, 'secret2': None}
            processing_complete = False
            if server_socket:
                server_socket.close()
            threading.Thread(target=start_server, args=(video_path, message)).start()
            return 'File uploaded and processing started. Please wait for the shared secrets to be generated.'

    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>Secure Video Steganography</title>
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
                background: url('https://hebbkx1anhila5yf.public.blob.vercel-storage.com/background2.jpg-HrmfSxhmb6xJPjQva3MMzlrepvfzu8.jpeg') no-repeat center center fixed;
                background-size: cover;
                padding: 20px;
                color: #fff;
            }

            .container {
                width: 100%;
                max-width: 600px;
                background: rgba(0, 0, 0, 0.8);
                padding: 2rem;
                border-radius: 15px;
                box-shadow: 0 0 30px rgba(255, 0, 255, 0.3);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 0, 255, 0.1);
                transform: translateY(20px);
                opacity: 0;
            }

            h1 {
                color: #ff00ff;
                text-align: center;
                margin-bottom: 2rem;
                font-size: 2rem;
                text-shadow: 0 0 10px rgba(255, 0, 255, 0.5);
            }

            form {
                display: flex;
                flex-direction: column;
                gap: 1.5rem;
                margin-bottom: 2rem;
            }

            input, textarea {
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 0, 255, 0.2);
                padding: 12px;
                border-radius: 8px;
                color: #fff;
                font-size: 1rem;
                transition: all 0.3s ease;
            }

            input:focus, textarea:focus {
                outline: none;
                border-color: #ff00ff;
                box-shadow: 0 0 15px rgba(255, 0, 255, 0.3);
            }

            textarea {
                min-height: 100px;
                resize: vertical;
            }

            input[type="file"] {
                padding: 20px;
                background: rgba(255, 0, 255, 0.1);
                cursor: pointer;
                position: relative;
                color: transparent; /* Added to hide "No file chosen" text */
            }

            input[type="file"]::-webkit-file-upload-button {
                visibility: hidden;
                width: 0;
            }

            input[type="file"]::before {
                content: '📁 Choose Video File';
                position: absolute;
                left: 50%;
                top: 50%;
                transform: translate(-50%, -50%);
                color: #ff00ff;
            }

            input[type="submit"] {
                background: linear-gradient(45deg, #ff00ff, #00ffff);
                color: #000;
                font-weight: bold;
                cursor: pointer;
                border: none;
                padding: 15px;
                text-transform: uppercase;
                letter-spacing: 2px;
                transition: all 0.3s ease;
            }

            input[type="submit"]:hover {
                transform: scale(1.02);
                box-shadow: 0 0 20px rgba(255, 0, 255, 0.4);
            }

            .secrets {
                background: rgba(255, 0, 255, 0.1);
                padding: 1.5rem;
                border-radius: 8px;
                border-left: 4px solid #ff00ff;
                margin-top: 2rem;
                opacity: 0;
                transform: translateX(-20px);
            }

            .secrets h2 {
                color: #ff00ff;
                margin-bottom: 1rem;
            }

            .secrets p {
                margin: 0.5rem 0;
                color: rgba(255, 255, 255, 0.9);
            }

            #refreshButton {
                width: 100%;
                padding: 12px;
                background: rgba(255, 0, 255, 0.2);
                border: 1px solid rgba(255, 0, 255, 0.3);
                color: #fff;
                border-radius: 8px;
                cursor: pointer;
                margin-top: 1rem;
                transition: all 0.3s ease;
            }

            #refreshButton:hover {
                background: rgba(255, 0, 255, 0.3);
                transform: scale(1.02);
            }

            @keyframes pulse {
                0% { box-shadow: 0 0 0 0 rgba(255, 0, 255, 0.4); }
                70% { box-shadow: 0 0 0 10px rgba(255, 0, 255, 0); }
                100% { box-shadow: 0 0 0 0 rgba(255, 0, 255, 0); }
            }

            .pulse {
                animation: pulse 2s infinite;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="animate-element">SECURE VIDEO STEGANOGRAPHY</h1>
            <form method="post" enctype="multipart/form-data" class="animate-element">
                <input type="file" name="file" accept="video/*" required>
                <textarea name="message" placeholder="Enter your secret message" required></textarea>
                <input type="submit" value="Upload & Process" class="pulse">
            </form>
            <div class="secrets animate-element">
                <h2>Shared Secrets</h2>
                <p>Secret 1: <span id="secret1">{{ shared_secrets['secret1'] or 'Not generated yet' }}</span></p>
                <p>Secret 2: <span id="secret2">{{ shared_secrets['secret2'] or 'Not generated yet' }}</span></p>
                <p>Status: <span id="status">{{ 'Processing complete' if processing_complete else 'Processing...' }}</span></p>
                <button id="refreshButton" onclick="refreshSecrets()">Refresh Status</button>
            </div>
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
                    targets: '.animate-element',
                    opacity: [0, 1],
                    translateY: [20, 0],
                    delay: anime.stagger(200),
                    duration: 800,
                    easing: 'easeOutExpo'
                });

                // Animate secrets section if it exists
                if (document.querySelector('.secrets')) {
                    anime({
                        targets: '.secrets',
                        opacity: [0, 1],
                        translateX: [-20, 0],
                        duration: 800,
                        delay: 600,
                        easing: 'easeOutExpo'
                    });
                }
            });

            function refreshSecrets() {
                const button = document.getElementById('refreshButton');
                button.style.transform = 'scale(0.95)';

                anime({
                    targets: '.secrets',
                    backgroundColor: [
                        { value: 'rgba(255, 0, 255, 0.3)', duration: 200 },
                        { value: 'rgba(255, 0, 255, 0.1)', duration: 800 }
                    ],
                    easing: 'easeOutExpo'
                });

                fetch(window.location.href)
                    .then(response => response.text())
                    .then(html => {
                        const parser = new DOMParser();
                        const doc = parser.parseFromString(html, 'text/html');

                        ['secret1', 'secret2', 'status'].forEach(id => {
                            const element = document.getElementById(id);
                            const newValue = doc.getElementById(id).textContent;
                            if (element.textContent !== newValue) {
                                element.style.backgroundColor = 'rgba(255, 0, 255, 0.3)';
                                element.textContent = newValue;
                                setTimeout(() => {
                                    element.style.backgroundColor = 'transparent';
                                }, 1000);
                            }
                        });

                        setTimeout(() => {
                            button.style.transform = 'scale(1)';
                        }, 200);
                    });
            }
        </script>
    </body>
    </html>
    ''', shared_secrets=shared_secrets, processing_complete=processing_complete)


if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True, port=5000)