"""Load and parse Kubernetes log files and event files from specified directories."""

import os
from typing import Optional


SUPPORTED_EXTENSIONS = {".log", ".txt", ".out"}


def load_files(folder_path: str, file_type: str = "log") -> list[dict]:
    """Recursively scan a folder and return contents of supported files.

    Args:
        folder_path: Path to the folder to scan.
        file_type: Label for the file type ('log' or 'event').

    Returns:
        List of dicts with file_name, file_path, file_type, and content.
    """
    if not os.path.exists(folder_path):
        print(f"[WARNING] Folder not found: {folder_path}")
        return []

    if not os.path.isdir(folder_path):
        print(f"[WARNING] Path is not a directory: {folder_path}")
        return []

    files = []
    for root, _, filenames in os.walk(folder_path):
        for filename in sorted(filenames):
            ext = os.path.splitext(filename)[1].lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue

            file_path = os.path.join(root, filename)
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                files.append({
                    "file_name": filename,
                    "file_path": file_path,
                    "file_type": file_type,
                    "content": content,
                })
            except OSError as e:
                print(f"[WARNING] Could not read {file_path}: {e}")

    if not files:
        print(f"[INFO] No supported files found in: {folder_path}")

    return files


def load_logs(logs_folder: str) -> list[dict]:
    """Load all Kubernetes log files from the given folder."""
    return load_files(logs_folder, file_type="log")


def load_events(events_folder: Optional[str]) -> list[dict]:
    """Load all Kubernetes event files from the given folder."""
    if not events_folder:
        return []
    return load_files(events_folder, file_type="event")
