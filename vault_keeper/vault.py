"""vault-keeper - Local-first password manager with encryption and TOTP."""

import base64
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path
from getpass import getpass

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


VAULT_DIR = Path.home() / ".vault-keeper"
VAULT_FILE = VAULT_DIR / "vault.json"
KEY_FILE = VAULT_DIR / ".key.salt"


class VaultKeeper:
    def __init__(self):
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        if not CRYPTO_AVAILABLE:
            print("WARNING: cryptography not installed. Install with: pip install cryptography")
        self.fernet = None

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def setup(self):
        if KEY_FILE.exists() and VAULT_FILE.exists():
            print("Vault already exists. Use 'vault-keeper unlock' to access.")
            return
        salt = os.urandom(16)
        password = getpass("Create master password: ")
        confirm = getpass("Confirm master password: ")
        if password != confirm:
            print("Passwords do not match.")
            sys.exit(1)
        KEY_FILE.write_bytes(salt)
        self.fernet = Fernet(self._derive_key(password, salt))
        self._save({})
        print("Vault created successfully.")

    def unlock(self):
        if not KEY_FILE.exists():
            print("No vault found. Run 'vault-keeper setup' first.")
            sys.exit(1)
        salt = KEY_FILE.read_bytes()
        password = getpass("Master password: ")
        self.fernet = Fernet(self._derive_key(password, salt))
        try:
            self._load()
            print("Vault unlocked.")
        except Exception:
            print("Incorrect master password.")
            sys.exit(1)

    def _load(self) -> dict:
        if not VAULT_FILE.exists():
            return {}
        encrypted = VAULT_FILE.read_bytes()
        if self.fernet:
            return json.loads(self.fernet.decrypt(encrypted).decode())
        return {}

    def _save(self, data: dict):
        if self.fernet:
            VAULT_FILE.write_bytes(self.fernet.encrypt(json.dumps(data).encode()))

    def add(self, service: str, username: str = "", password: str = ""):
        data = self._load()
        if not password:
            password = secrets.token_urlsafe(24)
        data[service] = {"username": username, "password": password, "totp_secret": ""}
        self._save(data)
        print(f"Added: {service} (username: {username or '<none>'})")

    def get(self, service: str):
        data = self._load()
        entry = data.get(service)
        if not entry:
            print(f"No entry found for: {service}")
            return
        print(f"Service:  {service}")
        print(f"Username: {entry.get('username', '')}")
        print(f"Password: {entry.get('password', '')}")
        if entry.get("totp_secret"):
            print(f"TOTP:     {self._totp(entry['totp_secret'])}")

    def list(self):
        data = self._load()
        if not data:
            print("No entries in vault.")
            return
        print(f"{'Service':<30} {'Username':<20}")
        print("-" * 50)
        for svc, entry in sorted(data.items()):
            print(f"{svc:<30} {entry.get('username', ''):<20}")

    def delete(self, service: str):
        data = self._load()
        if data.pop(service, None):
            self._save(data)
            print(f"Deleted: {service}")
        else:
            print(f"No entry found: {service}")

    def totp_setup(self, service: str, secret: str):
        data = self._load()
        if service not in data:
            print(f"Service '{service}' not found. Add it first.")
            return
        data[service]["totp_secret"] = secret
        self._save(data)
        print(f"TOTP configured for {service}")

    def _totp(self, secret: str) -> str:
        try:
            import pyotp
            totp = pyotp.TOTP(secret)
            return totp.now()
        except ImportError:
            return "TOTP: install pyotp (pip install pyotp)"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Local-first password manager")
    parser.add_argument("action", choices=["setup", "add", "get", "list", "delete", "totp"], nargs="?")
    parser.add_argument("args", nargs="*", help="arguments for the action")
    args = parser.parse_args()

    vk = VaultKeeper()

    if args.action is None:
        parser.print_help()
        return

    if args.action == "setup":
        vk.setup()
        return

    vk.unlock()

    if args.action == "add":
        svc = args.args[0] if args.args else input("Service name: ")
        user = args.args[1] if len(args.args) > 1 else input("Username (optional): ")
        vk.add(svc, user)
    elif args.action == "get":
        svc = args.args[0] if args.args else input("Service name: ")
        vk.get(svc)
    elif args.action == "list":
        vk.list()
    elif args.action == "delete":
        svc = args.args[0] if args.args else input("Service name: ")
        vk.delete(svc)
    elif args.action == "totp":
        svc = args.args[0] if args.args else input("Service name: ")
        secret = args.args[1] if len(args.args) > 1 else input("TOTP secret: ")
        vk.totp_setup(svc, secret)


if __name__ == "__main__":
    main()
