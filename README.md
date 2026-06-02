# Vault Keeper

A local-first password manager with encryption, TOTP support, and CLI/terminal UI.

## Features

- Encrypted local storage (AES-256-GCM)
- TOTP (time-based one-time password) generation
- CLI and terminal UI modes
- Search and filter
- CSV export/import
- Clipboard integration

## Quick Start

```bash
pip install -e .
vault init          # Create a new vault (sets master password)
vault add github    # Add a new entry
vault list          # List all entries
vault get github    # Show entry details
vault totp github   # Generate TOTP code
```
