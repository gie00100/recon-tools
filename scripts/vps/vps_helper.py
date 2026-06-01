"""
VPS Connection Helper — reads credentials from vps_config.ini
All scripts in scripts/vps/ should import this instead of hardcoding credentials.
"""

import configparser
import paramiko
from pathlib import Path


def get_vps_config():
    """Read VPS config from vps_config.ini"""
    config = configparser.ConfigParser()
    config_path = Path(__file__).parent.parent.parent / "vps_config.ini"

    if not config_path.exists():
        raise FileNotFoundError(
            f"VPS config not found at {config_path}\n"
            f"Copy vps_config.example.ini → vps_config.ini and fill in your credentials."
        )

    config.read(config_path)
    return {
        "host": config.get("vps", "host"),
        "user": config.get("vps", "user"),
        "password": config.get("vps", "password"),
        "port": config.getint("vps", "port", fallback=22),
        "remote_path": config.get("vps", "remote_path", fallback="/root/recon-tools"),
    }


def connect_vps():
    """Create and return an SSH connection to the VPS."""
    cfg = get_vps_config()
    print(f"[*] Connecting to VPS ({cfg['host']})...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        cfg["host"],
        port=cfg["port"],
        username=cfg["user"],
        password=cfg["password"],
        timeout=10,
        look_for_keys=False,
        allow_agent=False,
    )
    return ssh, cfg


def run_remote(ssh, cmd, label=None, silent=False):
    """Execute a command on the VPS and return output."""
    if label and not silent:
        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode("utf-8", errors="ignore").strip()
    err = stderr.read().decode("utf-8", errors="ignore").strip()
    if out and not silent:
        print(out)
    if err and not silent:
        print(f"STDERR: {err}")
    return out
