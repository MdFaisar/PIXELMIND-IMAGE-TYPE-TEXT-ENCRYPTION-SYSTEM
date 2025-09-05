# 🔐 PixelMind - Image Type Encryption System

## 📖 Project Overview

PixelMind is an advanced text-to-image encryption system designed to transform sensitive text files into innocent-looking images and secure PDF documents. This innovative application provides a powerful and user-friendly method to protect confidential information through unique steganography-inspired encryption techniques.

## 🚀 Live Demonstration

[![Live Demo](https://img.shields.io/badge/Live-Demo-success?style=for-the-badge)](https://pixelminds.pythonanywhere.com/)

## ✨ Key Features

- **Text-to-Image Encryption**: Seamlessly convert text files into encrypted images
- **Multi-File Support**: Encrypt multiple text files simultaneously
- **PDF Compilation**: Organize encrypted images into secure PDF documents
- **Secure Decryption**: Easily retrieve original files with proper credentials
- **Web Interface**: Intuitive and user-friendly application
- **Multi-Format Compatibility**: Supports various text file formats

## 🛠 Technology Stack

### Prerequisites

Before installation, ensure you have the following technologies installed:

#### 1. Python
- Version: 3.6+ recommended
- Download: [Python Official Website](https://www.python.org/downloads/)
- Verification:
  ```bash
  python --version
  ```

#### 2. Firebase Project
- Create a Firebase project at [Firebase Console](https://console.firebase.google.com/)
- Enable Firestore Database in your Firebase project
- Generate a service account key for Firebase Admin SDK
- Download the service account JSON file (keep it secure)

#### 3. pip (Python Package Manager)
- Typically installed with Python
- Verification:
  ```bash
  pip --version
  ```

#### 4. Virtual Environment (Recommended)
- Install virtualenv:
  ```bash
  pip install virtualenv
  ```

## 🚀 Installation Guide

### 1. Clone the Repository
```bash
git clone https://github.com/UnisysUIP/2025-File-encryption.git
cd 2025-File-encryption
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Create Secret key by running the following code and paste it in the .env file:
```bash
import secrets
print(secrets.token_hex(32))  # Generates a 64-character hexadecimal string
```
### 4. Environment Configuration

#### Create .env File
Create a `.env` file in the project root with the following configurations:

```plaintext
# Flask Secret Key (Use a strong, unique value)
SECRET_KEY=your_very_secret_and_unique_key

# Firebase Configuration (Get from Firebase Console > Project Settings > Service Accounts)
FIREBASE_TYPE=service_account
FIREBASE_PROJECT_ID=your_firebase_project_id
FIREBASE_PRIVATE_KEY_ID=your_private_key_id
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nyour_private_key_here\n-----END PRIVATE KEY-----\n"
FIREBASE_CLIENT_EMAIL=your_service_account_email
FIREBASE_CLIENT_ID=your_client_id
FIREBASE_AUTH_URI=https://accounts.google.com/o/oauth2/auth
FIREBASE_TOKEN_URI=https://oauth2.googleapis.com/token
FIREBASE_AUTH_PROVIDER_X509_CERT_URL=https://www.googleapis.com/oauth2/v1/certs
FIREBASE_CLIENT_X509_CERT_URL=your_client_cert_url

# Google OAuth Configuration (Get from Google Cloud Console)
GOOGLE_CLIENT_ID=your_google_oauth_client_id
GOOGLE_CLIENT_SECRET=your_google_oauth_client_secret

# Get the Key from Groq cloud - llama3.3-70B-Versatile -- [link](https://console.groq.com/keys)
CHATBOT_API_KEY=your_groq_llama3.3-70B-Versatile_API_Key

# Default Admin Credentials (Change in production)
ADMIN_USERNAME=guest
ADMIN_PASSWORD=guest

API_URL=https://api.groq.com/openai/v1/chat/completions
```


### 5. Run the Application
```bash
python run.py
```

### 6. Access the Application
Open your web browser and navigate to:
```
http://localhost:5000
```

## 📂 Project Structure

```
PixelMind/
│
├── app.py                 # Main Flask application
├── database.py            # Database interaction module
├── image_operations.py    # Image encryption/decryption logic
├── pdf_operations.py      # PDF generation module
├── chatbot_service.py     # Chatbot interaction service
│
├── templates/             # HTML templates
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
│   └── other html pages
│
├── static/                # Static assets
│   ├── css/
│   └── js/
│
├── uploads/               # Temporary file storage
├── .env                   # Environment configuration
└── requirements.txt       # Project dependencies
```

## 🔐 Login Credentials

- **Default Credentials (credential bypass)**:
  - Username: `guest`
  - Password: `guest`
## 🛡️ Security Considerations

- Designed for educational purposes
- Not suitable for military-grade security
- Implement HTTPS in production
- Regularly update dependencies
- Use strong, unique passwords
- Consider additional authentication mechanisms

## 🔄 Contribution Guidelines

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request


## 👥 Contributors

- Mohammed Faisar A - [MdFaisar]
- Ram Kumar R - [rkcoder7]
- Gowtham K - [Gowtham0614]
- Rakshita K - [Rakshita-31]

## 🙏 Acknowledgments

- Flask Web Framework
- Pillow Image Processing
- PyMuPDF
- Firebase Firestore
- Google OAuth 2.0
- Authlib
