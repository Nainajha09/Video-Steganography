# Video-Steganography
🔒 Secure video-based message embedding using AES encryption and a dual Diffie-Hellman key exchange mechanism


📜 Project Overview
This project implements a high-security video steganography technique by embedding encrypted messages within video frames. It ensures privacy, data integrity, and confidentiality using:

✅ AES (Advanced Encryption Standard) for encrypting messages before embedding
✅ Dual Diffie-Hellman key exchange for secure key management
✅ Frame and pixel-based embedding to maintain high visual quality
✅ Efficient video frame decomposition & reconstruction for seamless data hiding

By leveraging these techniques, this system achieves secure and undetectable communication through videos.

🛠️ Technologies Used
- Python 🐍
- OpenCV – For video processing
- NumPy – For array and pixel manipulation
- PyCryptodome – For AES encryption
- Diffie-Hellman Algorithm – For key exchange

📌 Features

✔️ Secure Encryption: Messages are encrypted using AES before embedding

✔️ Key Management: Dual Diffie-Hellman key exchange ensures secure key distribution

✔️ Frame-based Hiding: Data is embedded within specific video frames and pixels

✔️ High Visual Quality: Original video appearance is preserved while ensuring security

✔️ Message Extraction: Securely extract and decrypt the hidden message from the video


