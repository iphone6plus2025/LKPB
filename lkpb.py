#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

# Statistics
stats_count = 0
stats_size = 0

def show_help():
    help_text = """
Usage: lkpb [OPTION]... [PATH]...
Secure file encryption tool using AES-256-CBC and HMAC-SHA256.

Options:
  -e, --encrypt    Encryption mode. Removes original, creates .cr.
  -d, --decrypt    Decryption mode. Removes .cr, restores original.
  -k, -f [FILE]    Path to the key file (required).
  -h, --help       Display this help and exit.

License: BSD 3-Clause. Full text available at https://opensource.org/licenses/BSD-3-Clause

Examples:
  python lkpb.py -e -k key.bin ./documents
  python lkpb.py -d -f my_key .
"""
    print(help_text)
    sys.exit(0)

def get_key(key_path):
    if not os.path.exists(key_path):
        print(f"lkpb: cannot access key: '{key_path}': No such file", file=sys.stderr)
        sys.exit(1)
    with open(key_path, "rb") as kf:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(kf.read())
        return digest.finalize()

def encrypt_file(file_path, key):
    global stats_count, stats_size
    current_script = os.path.basename(__file__)
    
    if file_path.endswith(".cr") or os.path.basename(file_path) == current_script:
        return 
    
    file_size = os.path.getsize(file_path)
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    h = hmac.HMAC(key, hashes.SHA256(), backend=backend)
    h.update(iv)

    tmp_name = file_path + ".tmp"
    try:
        with open(file_path, "rb") as f_in, open(tmp_name, "wb") as f_out:
            f_out.write(b"\x00" * 48) # Header (IV + HMAC)
            while True:
                chunk = f_in.read(64 * 1024)
                if not chunk: break
                if len(chunk) < 64 * 1024:
                    pad_len = 16 - (len(chunk) % 16)
                    chunk += bytes([pad_len] * pad_len)
                ct_chunk = encryptor.update(chunk)
                h.update(ct_chunk)
                f_out.write(ct_chunk)
            f_out.write(encryptor.finalize())
            mac = h.finalize()
            f_out.seek(0)
            f_out.write(iv + mac)
        os.replace(tmp_name, file_path + ".cr")
        os.remove(file_path)
        stats_count += 1
        stats_size += file_size
        print(f"done: {file_path}.cr")
    except Exception as e:
        print(f"error: {file_path}: {e}", file=sys.stderr)
        if os.path.exists(tmp_name): os.remove(tmp_name)

def decrypt_file(file_path, key):
    global stats_count, stats_size
    if not file_path.endswith(".cr"):
        return

    backend = default_backend()
    IV_LEN, HMAC_LEN = 16, 32
    try:
        with open(file_path, "rb") as f:
            iv = f.read(IV_LEN)
            saved_mac = f.read(HMAC_LEN)
            if len(iv) < IV_LEN: return
            
            h = hmac.HMAC(key, hashes.SHA256(), backend=backend)
            h.update(iv)
            data_pos = f.tell()
            while True:
                chunk = f.read(64 * 1024)
                if not chunk: break
                h.update(chunk)
            try:
                h.verify(saved_mac)
            except:
                print(f"fail: {file_path}: integrity check failed", file=sys.stderr)
                return

            f.seek(data_pos)
            decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend).decryptor()
            out_name = file_path.replace(".cr", "")
            with open(out_name, "wb") as f_out:
                last_chunk = b""
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk: break
                    if last_chunk: f_out.write(decryptor.update(last_chunk))
                    last_chunk = chunk
                final_part = decryptor.update(last_chunk) + decryptor.finalize()
                pad_len = final_part[-1]
                f_out.write(final_part[:-pad_len] if 0 < pad_len <= 16 else final_part)
        file_size = os.path.getsize(file_path)
        os.remove(file_path)
        stats_count += 1
        stats_size += file_size
        print(f"done: {out_name}")
    except Exception as e:
        print(f"error: {file_path}: {e}", file=sys.stderr)

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or "-h" in args or "--help" in args:
        show_help()

    mode, key_file, target = None, None, None
    i = 0
    while i < len(args):
        if args[i] in ["-e", "--encrypt"]: mode = "-e"
        elif args[i] in ["-d", "--decrypt"]: mode = "-d"
        elif args[i] in ["-k", "-f"]:
            if i + 1 < len(args):
                key_file = args[i+1]
                i += 1
        else: target = args[i]
        i += 1

    if not mode or not key_file or not target:
        print("lkpb: missing required arguments. Use --help.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(target):
        print(f"lkpb: {target}: No such file or directory", file=sys.stderr)
        sys.exit(1)

    key = get_key(key_file)
    if os.path.isfile(target):
        if mode == "-e": encrypt_file(target, key)
        else: decrypt_file(target, key)
    else:
        for root, dirs, files in os.walk(target):
            for name in files:
                if name.startswith('.'): continue
                full_path = os.path.join(root, name)
                if mode == "-e": encrypt_file(full_path, key)
                else: decrypt_file(full_path, key)

    action = "encrypted" if mode == "-e" else "decrypted"
    print(f"\n--- Summary ---\nFiles: {stats_count}\nVolume: {stats_size/(1024*1024):.2f} MB\nStatus: {action}\n---------------")
