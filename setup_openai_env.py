#!/usr/bin/env python3
"""Safely configure the local OpenAI API key for the Suricata agent."""

from __future__ import annotations

import getpass
import os
import secrets
import stat
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
ENV_PATH = PROJECT_ROOT / ".env"


def target_uid_gid() -> tuple[int, int]:
    """Use the sudo caller as owner when this script is run with sudo."""
    if os.geteuid() == 0 and os.environ.get("SUDO_UID"):
        uid = int(os.environ["SUDO_UID"])
        gid = int(os.environ.get("SUDO_GID", uid))
        return uid, gid
    return os.getuid(), os.getgid()


def write_locked_env(api_key: str) -> None:
    uid, gid = target_uid_gid()
    random_suffix = secrets.token_hex(8)
    temporary = ENV_PATH.with_name(f".{ENV_PATH.name}.{random_suffix}.tmp")
    data = f"OPENAI_API_KEY={api_key}\n"

    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, 0o600)
        os.replace(temporary, ENV_PATH)
        os.chown(ENV_PATH, uid, gid)
        os.chmod(ENV_PATH, 0o600)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise


def main() -> int:
    print(f"OpenAI key setup for {PROJECT_ROOT}")
    print("The key will not be displayed while you type.")

    if ENV_PATH.exists():
        answer = input(f"{ENV_PATH} already exists. Replace it? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("No changes made.")
            return 0

    try:
        api_key = getpass.getpass("Paste OPENAI_API_KEY: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled; no changes made.")
        return 1

    if not api_key:
        print("Error: an empty API key was not saved.", file=sys.stderr)
        return 1
    if any(char.isspace() for char in api_key):
        print("Error: the API key contains whitespace; check the pasted value.", file=sys.stderr)
        return 1
    if not api_key.startswith("sk-"):
        print("Warning: the value does not start with 'sk-'; verify it before continuing.")
        answer = input("Save this value anyway? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("No changes made.")
            return 1

    try:
        write_locked_env(api_key)
    except OSError as exc:
        print(f"Error: could not securely write {ENV_PATH}: {exc}", file=sys.stderr)
        return 1

    mode = stat.S_IMODE(ENV_PATH.stat().st_mode)
    owner = ENV_PATH.stat().st_uid
    print(f"Saved {ENV_PATH}")
    print(f"Owner UID: {owner}; permissions: {mode:04o}")
    print("The agent will load this file automatically on its next start.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
