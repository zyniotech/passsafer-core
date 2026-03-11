<div align="center">
  <h1>PassSafer – Core Engine & Security Audit</h1>
  <p><strong>The encryption logic behind the highly secure local password manager.</strong></p>
</div>

---

## 🔒 Source-Available for Maximum Transparency

When it comes to security, there should be no secrets. **PassSafer** is a commercial offline password manager that relies 100% on local data storage.

To justify the trust of our users, we are making the critical **core source code (backend & cryptography)** available here for public inspection (Security Auditing) under a "Source-Available" model.

We have nothing to hide. Security experts and interested users can trace the exact path of their data here—from input to encryption on the hard drive.

### What is included in this repository?
This repository contains **exclusively** the backend logic and the communication bridge of the Electron application to make our encryption mechanisms transparent:

*   `main.js`: The main process. This is where the core logic happens. Here you will find our AES-256-CBC encryption, the PBKDF2 (100,000 iterations) key derivation, secure local file storage, and the IPC handlers.
*   `preload.js`: The secure communication bridge (Context Isolation) between the user interface and the main process.

*Note: The code for the frontend (UI/UX) is not included here to protect our proprietary design.*

## 🛒 Purchase the Full App
Do you want to use the full, ready-to-use app with its beautiful Dark Mode interface?

**PassSafer is available at:**
👉 https://payhip.com/b/Sl2Xo

### Features of the full version:
- Zero-Knowledge Architecture (Offline-First)
- Encrypted file attachments up to 100MB
- Single-Page Application (Dark Mode UI)
- CSPRNG Password Generator & Auto-Logout
- Encrypted Export & Backup features

## ⚖️ Licensing & Copyright
**IMPORTANT:** This repository is **not** under an Open Source license (like MIT/GPL).

The source code is provided here **exclusively for transparency and auditing purposes**. Copying, modifying, compiling, reselling, or any kind of commercial or non-commercial redistribution is strictly prohibited. It is **"All Rights Reserved"** by Zynio Tech.

Please read the included `LICENSE.txt` for the full legal terms.