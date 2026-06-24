"""
DevOps File Loader

Recursively scans a directory to identify and classify DevOps configuration
files including GitHub Actions, GitLab CI/CD, Dockerfiles, Terraform,
Kubernetes, Helm, and Ansible files.
"""

import os
from typing import List, Dict


FILE_TYPE_MAP = {
    "github-actions": "GitHub Actions Workflow",
    "gitlab": "GitLab CI/CD Pipeline",
    "docker": "Dockerfile",
    "terraform": "Terraform Configuration",
    "kubernetes": "Kubernetes Manifest",
    "helm": "Helm Values",
    "ansible": "Ansible Playbook",
}


def classify_file(file_path: str) -> str:
    """Determine the DevOps file type based on path and filename patterns."""
    normalized = file_path.replace("\\", "/").lower()
    basename = os.path.basename(file_path).lower()

    if ".github/workflows" in normalized or "github-actions" in normalized:
        if basename.endswith((".yml", ".yaml")):
            return "GitHub Actions Workflow"

    if "gitlab" in normalized and basename in ("gitlab-ci.yml", ".gitlab-ci.yml"):
        return "GitLab CI/CD Pipeline"
    if "gitlab" in normalized and basename.endswith((".yml", ".yaml")):
        return "GitLab CI/CD Pipeline"

    if basename == "dockerfile" or basename.startswith("dockerfile."):
        return "Dockerfile"

    if basename.endswith(".tf"):
        return "Terraform Configuration"

    if "kubernetes" in normalized or "k8s" in normalized:
        if basename.endswith((".yml", ".yaml")):
            return "Kubernetes Manifest"

    if "helm" in normalized and basename.endswith((".yml", ".yaml")):
        return "Helm Values"

    if "ansible" in normalized and basename.endswith((".yml", ".yaml")):
        return "Ansible Playbook"

    return "Unknown"


def load_files(directory: str) -> List[Dict[str, str]]:
    """
    Recursively scan a directory and return a list of identified DevOps files.

    Each entry contains:
        - file_path: absolute path to the file
        - file_name: basename of the file
        - file_type: classified DevOps file type
        - content: raw file content as a string
    """
    if not os.path.isdir(directory):
        raise FileNotFoundError(f"Directory not found: {directory}")

    results = []

    for root, _dirs, files in os.walk(directory):
        for filename in sorted(files):
            file_path = os.path.join(root, filename)
            file_type = classify_file(file_path)

            if file_type == "Unknown":
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except (IOError, UnicodeDecodeError):
                continue

            results.append({
                "file_path": file_path,
                "file_name": filename,
                "file_type": file_type,
                "content": content,
            })

    return results
