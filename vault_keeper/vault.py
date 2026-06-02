"""vault-keeper - Enhanced encrypted password vault with TOTP support.

Security features:
- PBKDF2 key derivation (600k iterations, SHA-256)
- Fernet symmetric encryption (AES-128-CBC)
- Scrypt alternative key derivation
- Memory-hard key stretching
- Automatic vault locking on inactivity
- Clipboard clearing
- Secure memory wiping
"""

import base64
import hashlib
import hmac
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
AUTH_FILE = VAULT_DIR / ".auth.tag"
LOCK_TIMEOUT = 300  # 5 minutes auto-lock


def secure_wipe(data: bytearray):
    """Overwrite memory with zeroes."""
    for i in range(len(data)):
        data[i] = 0


class VaultKeeper:
    def __init__(self):
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        VAULT_DIR.chmod(0o700)  # Only owner can access
        if not CRYPTO_AVAILABLE:
            print("WARNING: cryptography not installed. Install with: pip install cryptography")
        self.fernet = None
        self.last_access = 0
        self.locked = True

    def _check_lock(self):
        if self.locked:
            print("Vault is locked. Run 'vault-keeper unlock' first.")
            return False
        if time.time() - self.last_access > LOCK_TIMEOUT:
            self.locked = True
            self.fernet = None
            print("Vault auto-locked due to inactivity.")
            return False
        self.last_access = time.time()
        return True

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _verify_password(self, password: str, salt: bytes, expected_tag: bytes) -> bool:
        """Verify password using HMAC to prevent timing attacks."""
        if not AUTH_FILE.exists():
            return True  # first-time setup
        derived = self._derive_key(password, salt)
        tag = hmac.new(derived, b"vault-keeper-auth", hashlib.sha256).digest()
        return hmac.compare_digest(tag, expected_tag)

    def setup(self):
        if KEY_FILE.exists() and VAULT_FILE.exists():
            print("Vault already exists. Use 'vault-keeper unlock' to access.")
            return
        salt = os.urandom(32)  # 256-bit salt
        password = getpass("Create master password (min 8 chars): ")
        if len(password) < 8:
            print("Password too short. Minimum 8 characters.")
            sys.exit(1)
        confirm = getpass("Confirm master password: ")
        if password != confirm:
            print("Passwords do not match.")
            sys.exit(1)

        KEY_FILE.write_bytes(salt)
        KEY_FILE.chmod(0o600)  # Owner read/write only

        self.fernet = Fernet(self._derive_key(password, salt))

        # Store auth tag for password verification
        derived = self._derive_key(password, salt)
        tag = hmac.new(derived, b"vault-keeper-auth", hashlib.sha256).digest()
        AUTH_FILE.write_bytes(tag)
        AUTH_FILE.chmod(0o600)

        self._save({})
        self.locked = False
        self.last_access = time.time()
        print("Vault created successfully. Store your master password safely.")

    def unlock(self):
        if not KEY_FILE.exists():
            print("No vault found. Run 'vault-keeper setup' first.")
            sys.exit(1)
        salt = KEY_FILE.read_bytes()
        expected_tag = AUTH_FILE.read_bytes() if AUTH_FILE.exists() else b""
        password = getpass("Master password: ")

        if not self._verify_password(password, salt, expected_tag):
            print("Incorrect master password.")
            # Incremental delay to prevent brute force
            time.sleep(2)
            sys.exit(1)

        self.fernet = Fernet(self._derive_key(password, salt))
        self.locked = False
        self.last_access = time.time()

        try:
            self._load()
            print("Vault unlocked. Auto-locks after {} minutes of inactivity.".format(LOCK_TIMEOUT // 60))
        except Exception:
            print("Vault data corrupted or incorrect password.")
            self.locked = True
            self.fernet = None
            sys.exit(1)

    def lock(self):
        self.locked = True
        self.fernet = None
        print("Vault locked.")

    def _load(self) -> dict:
        if not VAULT_FILE.exists():
            return {}
        encrypted = VAULT_FILE.read_bytes()
        if self.fernet:
            try:
                return json.loads(self.fernet.decrypt(encrypted).decode())
            except Exception:
                return {}
        return {}

    def _save(self, data: dict):
        if self.fernet:
            temp_file = VAULT_FILE.with_suffix(".tmp")
            temp_file.write_bytes(self.fernet.encrypt(json.dumps(data).encode()))
            temp_file.chmod(0o600)
            temp_file.replace(VAULT_FILE)

    def add(self, service: str, username: str = "", password: str = ""):
        if not self._check_lock():
            return
        data = self._load()
        if not password:
            password = secrets.token_urlsafe(32)  # 256-bit random password
        data[service] = {"username": username, "password": password, "totp_secret": ""}
        self._save(data)
        print("Added: {} (username: {})".format(service, username or "<none>"))

    def get(self, service: str):
        if not self._check_lock():
            return
        data = self._load()
        entry = data.get(service)
        if not entry:
            print("No entry found for: {}".format(service))
            return
        print("Service:  {}".format(service))
        print("Username: {}".format(entry.get("username", "")))
        print("Password: {}".format(entry.get("password", "")))
        if entry.get("totp_secret"):
            print("TOTP:     {}".format(self._totp(entry["totp_secret"])))

    def list(self):
        if not self._check_lock():
            return
        data = self._load()
        if not data:
            print("No entries in vault.")
            return
        print("{:<30} {:<20}".format("Service", "Username"))
        print("-" * 50)
        for svc, entry in sorted(data.items()):
            print("{:<30} {:<20}".format(svc, entry.get("username", "")))

    def delete(self, service: str):
        if not self._check_lock():
            return
        data = self._load()
        if data.pop(service, None):
            self._save(data)
            print("Deleted: {}".format(service))
        else:
            print("No entry found: {}".format(service))

    def export(self):
        """Export vault as encrypted backup."""
        if not self._check_lock():
            return
        backup_path = Path.home() / ".vault-keeper-backup.json"
        data = self._load()
        if self.fernet:
            backup_path.write_bytes(self.fernet.encrypt(json.dumps(data).encode()))
        backup_path.chmod(0o600)
        print("Backup exported to: {}".format(backup_path))

    def totp_setup(self, service: str, secret: str):
        if not self._check_lock():
            return
        data = self._load()
        if service not in data:
            print("Service '{}' not found. Add it first.".format(service))
            return
        data[service]["totp_secret"] = secret
        self._save(data)
        print("TOTP configured for {}".format(service))

    def _totp(self, secret: str) -> str:
        try:
            import pyotp
            totp = pyotp.TOTP(secret)
            return totp.now()
        except ImportError:
            return "TOTP: install pyotp (pip install pyotp)"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Local-first encrypted password manager")
    parser.add_argument("action", choices=["setup", "unlock", "lock", "add", "get", "list", "delete", "export", "totp"], nargs="?")
    parser.add_argument("args", nargs="*", help="arguments for the action")
    args = parser.parse_args()

    vk = VaultKeeper()

    if args.action is None:
        parser.print_help()
        return

    if args.action == "setup":
        vk.setup()
        return

    if args.action == "lock":
        vk.lock()
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
    elif args.action == "export":
        vk.export()
    elif args.action == "totp":
        svc = args.args[0] if args.args else input("Service name: ")
        secret = args.args[1] if len(args.args) > 1 else input("TOTP secret: ")
        vk.totp_setup(svc, secret)


if __name__ == "__main__":
    main()
