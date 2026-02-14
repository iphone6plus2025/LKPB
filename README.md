### LKPB

LKPB is a minimalist file encryptor written in Python, implementing:
	•	AES-256-CBC
	•	HMAC-SHA256 (integrity check)
	•	Stream-based file processing
	•	Recursive directory handling

The project focuses on simplicity, transparent logic, and predictable behavior.

🔐 Architecture

LKPB uses the scheme:

AES-256-CBC + HMAC-SHA256
	•	The key is derived as SHA256 of the key file contents
	•	A random IV (16 bytes) is generated for each file
	•	HMAC is calculated over: IV + ciphertext
	•	File header: IV (16B) + HMAC (32B)
	•	Followed by the encrypted content

File format:

[16 bytes IV][32 bytes HMAC][ciphertext...]

Encrypted files use the extension: .cr

⚙️ Features
	•	File encryption
	•	File decryption
	•	Recursive directory processing
	•	Statistics (file count, total size)
	•	Integrity verification via HMAC
	•	Atomic writing using a temporary .tmp file

🚀 Usage

Encrypt a file:

./lkpb -e -k keyfile path

Decrypt a file:

./lkpb -d -k keyfile path

Help:

./lkpb -h

📦 Requirements
	•	Python 3.8+
	•	cryptography library

Install dependency:

pip install cryptography

🛡 Security Features
	•	Separate HMAC to protect against data modification
	•	HMAC is verified before decryption
	•	Automatic deletion of the original file after a successful operation

⚠ Limitations
	•	Uses SHA256(keyfile) directly, no PBKDF2
	•	No format version in the header
	•	No AEAD support (e.g., AES-GCM)
	•	No protection against key reuse

📁 Purpose

LKPB is:
	•	A simple standalone CLI tool
	•	An educational AES + HMAC implementation
	•	A minimalist alternative to “heavy” crypto systems
	•	A controlled file encryptor without hidden