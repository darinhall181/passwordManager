# Password Manager

A secure, command-line based password manager built as a group project for a Computer Security class. This application allows users to securely store and retrieve passwords locally using strong encryption standards.

## Authors
- **Wayzaro Ariella-yve Taylor** (CASEID: WYT2)
- **Apeksha Malik** (CASEID: ASM250)
- **Darin Hall** (CASEID: DAH181)

## Features

- **Secure Local Storage**: Passwords are stored in a local file (`passwordManager.txt`).
- **Strong Encryption**: Uses **AES (Advanced Encryption Standard)** for encrypting passwords.
- **Key Derivation**: Implements **PBKDF2WithHmacSHA256** (Password-Based Key Derivation Function 2) with 1024 iterations and a 256-bit key length to derive encryption keys from your master password.
- **Salting**: utilizes a random 16-byte salt for each password file to protect against rainbow table attacks.
- **Master Password Protection**: Access to the password vault is protected by a master passcode.

## Getting Started

### Prerequisites

- Java Development Kit (JDK) 8 or higher.

### Compilation

Open your terminal or command prompt, navigate to the project directory, and run the following command to compile the source files:

```bash
javac Main.java encrypt.java
```

### Running the Application

To start the password manager, run:

```bash
java Main
```

## Usage

### 1. Initial Setup
When you run the application for the first time, it will detect that no password file exists (`passwordManager.txt`). You will be prompted to create an **initial passcode** (Master Password).

> **Important**: Remember this passcode! If you lose it, you will not be able to recover your stored passwords.

### 2. Main Menu
Once authenticated, you will be presented with the following options:

- **a : Add Password**
  - Enter a label (e.g., "Gmail", "Facebook").
  - Enter the password you want to store.
  - If the label already exists, the old password will be updated.

- **r : Read Password**
  - Enter the label of the password you wish to retrieve.
  - The application will decrypt and display the password.

- **q : Quit**
  - Exits the application.

## Security Architecture

This project demonstrates the implementation of fundamental cryptographic concepts:

1.  **Authentication**: The application verifies the user by encrypting the entered passcode with itself (derived key) and storing it. verification is done by attempting to decrypt this token.
2.  **Confidentiality**: All user passwords are encrypted using AES before being written to disk. The plaintext passwords are never stored.
3.  **Key Management**: The encryption key is never stored directly. Instead, it is dynamically generated each time the application runs using the User's Master Password and a stored cryptographic salt.

## Disclaimer

This software was developed for educational purposes as part of a Computer Security course. While it uses standard cryptographic libraries, it is intended for learning and demonstration.
