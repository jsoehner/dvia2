#!/usr/bin/env python3
"""
fetch_oci_cbom.py - Fetch OCI 1.1 / ORAS Attached CBOM & SBOM Artifacts

Discovers and fetches Cryptographic Bill of Materials (CBOM) or SBOM artifacts
attached to a container image in an OCI Distribution Spec v1.1+ registry
(GHCR, ECR, ACR, GAR, Docker Hub, Harbor) using the OCI Referrers API,
the ORAS CLI, or regctl without pulling or running the full container image.
"""

import sys
import os
import json
import argparse
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Dict, Any, List

CYCLONEDX_MEDIA_TYPES = [
    "application/vnd.cyclonedx+json",
    "application/x-cyclonedx+json",
    "application/vnd.cyclonedx",
    "application/spdx+json"
]


def resolve_image_ref(image_ref: str) -> Dict[str, str]:
    """Parse image reference into registry, repository, and tag/digest."""
    ref = image_ref.strip()
    tag = "latest"
    digest = ""

    if "@" in ref:
        image_part, digest = ref.split("@", 1)
    else:
        image_part = ref

    if ":" in image_part and not digest:
        image_name, tag = image_part.rsplit(":", 1)
    else:
        image_name = image_part

    parts = image_name.split("/", 1)
    if len(parts) == 1 or ("." not in parts[0] and ":" not in parts[0] and parts[0] != "localhost"):
        registry = "registry-1.docker.io"
        repository = f"library/{image_name}" if len(parts) == 1 else image_name
    else:
        registry = parts[0]
        repository = parts[1]

    return {
        "registry": registry,
        "repository": repository,
        "tag": tag,
        "digest": digest,
        "raw": image_ref
    }


def try_fetch_via_oras(image_ref: str, output_path: Path, artifact_type: Optional[str] = None) -> bool:
    """Attempt to discover and pull attached CBOM using ORAS CLI."""
    if not shutil_which("oras"):
        return False

    output_dir = output_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Querying OCI referrers via ORAS for {image_ref}...", file=sys.stderr)
    try:
        # Discover referrers
        discover_cmd = ["oras", "discover", image_ref, "-o", "json"]
        if artifact_type:
            discover_cmd.extend(["--artifact-type", artifact_type])
        
        proc = subprocess.run(discover_cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return False

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return False

        manifests = data.get("manifests", [])
        if not manifests:
            return False

        # Look for CycloneDX/CBOM manifest
        target_digest = None
        for m in manifests:
            m_type = m.get("artifactType") or m.get("mediaType", "")
            if any(c_type in m_type.lower() for c_type in ["cyclonedx", "cbom"]):
                target_digest = m.get("digest")
                break
        
        if not target_digest and manifests:
            target_digest = manifests[0].get("digest")

        if not target_digest:
            return False

        # Pull referrer blob/manifest to temp location
        target_ref = f"{image_ref.split('@')[0].split(':')[0]}@{target_digest}"
        pull_cmd = ["oras", "pull", target_ref, "-o", str(output_dir)]
        pull_proc = subprocess.run(pull_cmd, capture_output=True, text=True, check=False)
        if pull_proc.returncode == 0:
            # Check if output_path exists or if any .json was written
            if output_path.exists():
                print(f"[+] Successfully fetched attached CBOM via ORAS: {output_path}", file=sys.stderr)
                return True
            for candidate in output_dir.glob("*.json"):
                if candidate.name != output_path.name:
                    candidate.replace(output_path)
                    print(f"[+] Successfully fetched attached CBOM via ORAS -> {output_path}", file=sys.stderr)
                    return True
    except Exception as e:
        print(f"[-] ORAS fetch attempt failed: {e}", file=sys.stderr)

    return False


def try_fetch_via_regctl(image_ref: str, output_path: Path) -> bool:
    """Attempt discovery and retrieval using regclient / regctl."""
    if not shutil_which("regctl"):
        return False

    output_dir = output_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Querying OCI referrers via regctl for {image_ref}...", file=sys.stderr)
    try:
        # regctl artifact list --filter-artifact-type
        cmd = ["regctl", "artifact", "list", image_ref, "--format", "{{json .}}"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            manifests = data.get("manifests", [])
            for m in manifests:
                art_type = m.get("artifactType", "")
                if "cyclonedx" in art_type.lower() or "cbom" in art_type.lower():
                    m_digest = m.get("digest")
                    blob_ref = f"{image_ref.split('@')[0].split(':')[0]}@{m_digest}"
                    get_cmd = ["regctl", "artifact", "get", blob_ref]
                    with open(output_path, "wb") as f_out:
                        blob_proc = subprocess.run(get_cmd, stdout=f_out, stderr=subprocess.PIPE, check=False)
                    if blob_proc.returncode == 0 and output_path.stat().st_size > 0:
                        print(f"[+] Successfully fetched attached CBOM via regctl: {output_path}", file=sys.stderr)
                        return True
    except Exception as e:
        print(f"[-] regctl fetch attempt failed: {e}", file=sys.stderr)

    return False


def shutil_which(cmd: str) -> Optional[str]:
    import shutil
    return shutil.which(cmd)


def main():
    parser = argparse.ArgumentParser(description="Fetch OCI 1.1 / ORAS attached CBOM/SBOM artifacts from registries.")
    parser.add_argument("image", help="Container image reference (e.g. ghcr.io/org/repo:tag or image@sha256:...)")
    parser.add_argument("-o", "--output", type=Path, default=Path("oss/upstream_cbom.json"), help="Output path for fetched CBOM")
    parser.add_argument("--artifact-type", default="application/vnd.cyclonedx+json", help="Expected OCI artifactType filter")
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)

    # 1. Try ORAS CLI
    if try_fetch_via_oras(args.image, args.output, args.artifact_type):
        sys.exit(0)

    # 2. Try regctl CLI
    if try_fetch_via_regctl(args.image, args.output):
        sys.exit(0)

    print(f"[-] No attached OCI CBOM discovered for {args.image} via available tooling.", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
