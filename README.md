# Repositório SSI 24/25


# 📘 Guiões Práticos // Practical Guides

🔐 Throughout the practical guides, we explored essential cryptographic concepts such as symmetric and asymmetric ciphers, digital certificates (X.509), and key exchange mechanisms like Diffie-Hellman. These hands-on exercises helped solidify our understanding of how these techniques are applied in real-world secure systems, especially in the context of encrypted communication and user authentication.

# 🎓 Trabalho Prático // Project

## Grade: 16.4/20 ⭐️

📚 This project was developed as part of the Computer Systems Security course, in the 2nd semester of the 3rd year of the Bachelor's Degree in Computer Engineering at the University of Minho (2024/2025).

This project implements a secure file vault service, allowing users to store and share text files with guarantees of **authenticity**, **integrity**, and **confidentiality**. The system is built using a Python-based client-server architecture and leverages cryptographic mechanisms for secure communication and access control.

## 🧱 Main Features

- 🔑 Each user has a personal vault to store private files
- 👥 Support for group creation, management, and group-specific vaults
- 🔒 Files can be shared with users or groups, with read/write permissions
- 📁 Full command-line interface for adding, reading, sharing, and managing files
- ✅ Secure authentication using X.509 certificates stored in PKCS12 keystores
- 🔐 Encrypted communication between client and server using TLS
- 🧾 Server stores application state locally using the filesystem

## ⚙️ Technologies & Tools

- Python 3
- `cryptography` library for certificate handling
- X.509 and PKCS12 for user authentication and identity
- Custom command interpreter on the client side


## Authors
- A104276 - Afonso Dionísio
- A104356 - João Lobo
- A104439 - Rita Camacho
