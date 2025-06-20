# 🔐 Secure File Vault

Secure File Vault is a simple command-line Java application that allows users to securely upload and download encrypted files. The application supports role-based access control with `ADMIN` and `USER` roles and encrypts all files using AES encryption.

---

## 📦 Features

* 🔑 **User Authentication**

  * SHA-256 password hashing
  * Role-based access control (`ADMIN` / `USER`)
* 🗃️ **File Vault**

  * AES-encrypted file uploads
  * Decryption and download support
* 👤 **Admin Features**

  * Create new users with roles
  * View all registered users

---

## 🚀 Getting Started

### ✅ Prerequisites

* Java 8 or higher
* A terminal or command prompt

### 🧩 Compile

```bash
javac SecureFileVault.java
```

### ▶️ Run

```bash
java SecureFileVault
```

---

## 🔐 Default Admin Credentials

| Username | Password | Role  |
| -------- | -------- | ----- |
| admin    | admin123 | ADMIN |

---

## 📂 File Storage

* All uploaded files are stored in the `vault/` directory.
* Encrypted files are saved with a prefix: `username_filename`.

---

## 🔧 Admin Menu

1. **Create User** – Add new users and assign roles (`ADMIN` or `USER`)
2. **Upload File** – Encrypt and store a file in the vault
3. **Download File** – Decrypt a vault file to local storage
4. **View Users** – List all users and their roles
5. **Logout**

---

## 👤 User Menu

1. **Upload File** – Encrypt and store a file in the vault
2. **Download File** – Decrypt a vault file to local storage
3. **Logout**

---

## 🔒 Encryption Details

* **Algorithm**: AES (Advanced Encryption Standard)
* **Key Size**: 128-bit
* **Key Generation**: Done at runtime using `KeyGenerator`

---

## ⚠️ Limitations & Considerations

* AES key is generated at runtime and not persisted, so files encrypted in one session cannot be decrypted in another.
* No persistent user storage – users are stored in memory only and lost after shutdown.
* No input validation or brute-force protection – not recommended for production.

---

## 📘 Future Improvements

* Persist users and roles to a file or database.
* Persist AES encryption key or use password-based encryption.
* Add file listing per user.
* Implement secure password handling with salting.

---
