#!/usr/bin/env python3
"""
enrich_sbom_python.py - Enrich CycloneDX & SPDX SBOMs with Python Dependencies

Parses requirements.txt / pyproject.toml, resolves installed package versions
and transitive cryptographic/network dependencies via importlib.metadata (with
deterministic fallback for standard auth/crypto dependency trees), and merges
`pkg:pypi/<name>@<version>` components into oss/sbom.cyclonedx.json.

Why this is needed:
Anchore Syft's static `python-pip-requirements-cataloger` frequently skips or
under-reports unpinned (`>=`) requirements when running outside an active virtualenv,
and misses transitive cryptographic libraries (`cryptography`, `PyJWT`, `rsa`,
`urllib3`, `certifi`, `google-auth`) unless they are explicitly enriched.
"""

import importlib.metadata
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Known transitive security/crypto/network dependencies for common Python SDKs
# Used when packages are not all installed in the current interpreter environment.
KNOWN_TRANSITIVE_DEPS: Dict[str, List[Tuple[str, str]]] = {
    "msal": [
        ("PyJWT", "2.10.1"),
        ("cryptography", "44.0.0"),
        ("requests", "2.32.3"),
    ],
    "google-auth-oauthlib": [
        ("google-auth", "2.38.0"),
        ("requests-oauthlib", "2.0.0"),
    ],
    "google-auth": [
        ("rsa", "4.9"),
        ("pyasn1-modules", "0.4.1"),
        ("cachetools", "5.5.0"),
    ],
    "google-api-python-client": [
        ("google-auth", "2.38.0"),
        ("google-auth-httplib2", "0.2.0"),
        ("httplib2", "0.22.0"),
        ("uritemplate", "4.1.1"),
    ],
    "requests": [
        ("urllib3", "2.3.0"),
        ("certifi", "2025.1.31"),
        ("charset-normalizer", "3.4.1"),
        ("idna", "3.10"),
    ],
    "requests-oauthlib": [
        ("oauthlib", "3.2.2"),
        ("requests", "2.32.3"),
    ],
}


def normalize_pypi_name(name: str) -> str:
    """Normalize Python package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def get_installed_version(pkg_name: str) -> Optional[str]:
    """Query importlib.metadata for an installed package version."""
    for candidate in (pkg_name, normalize_pypi_name(pkg_name), pkg_name.replace("-", "_")):
        try:
            return importlib.metadata.version(candidate)
        except importlib.metadata.PackageNotFoundError:
            continue
    return None


def parse_requirement_line(line: str) -> Optional[Tuple[str, str]]:
    """
    Parse a PEP 508 requirement line (e.g. 'cryptography>=41.0.0', 'msal==1.31.0').
    Returns (package_name, fallback_version) or None for comments/blanks/options.
    """
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "git+", "http:", "https:")):
        return None
    # Strip environment markers
    line = line.split(";", 1)[0].strip()
    # Strip extras like pkg[extra]
    m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(.*)$", line)
    if not m:
        return None
    pkg_name = m.group(1).strip()
    spec = m.group(2).strip()
    version = "latest"
    if spec:
        vm = re.search(r"(?:==|~=|>=|<=|>|<)\s*([0-9][0-9A-Za-z.\-_]*)", spec)
        if vm:
            version = vm.group(1)
    return pkg_name, version


def discover_python_dependencies(project_dir: Path) -> List[Dict[str, str]]:
    """Discover direct and transitive Python dependencies from project manifests."""
    discovered: Dict[str, Dict[str, str]] = {}

    def register_pkg(raw_name: str, fallback_ver: str, scope: str = "required"):
        norm = normalize_pypi_name(raw_name)
        if not norm or norm in ("python", "pip", "setuptools", "wheel"):
            return
        installed_ver = get_installed_version(raw_name)
        resolved_ver = installed_ver or fallback_ver or "latest"
        if norm not in discovered or (discovered[norm]["version"] == "latest" and resolved_ver != "latest"):
            purl = f"pkg:pypi/{norm}@{resolved_ver}"
            discovered[norm] = {
                "name": norm,
                "version": resolved_ver,
                "purl": purl,
                "type": "library",
                "scope": scope,
                "bom-ref": purl,
            }

    # 1. Parse requirements*.txt files
    req_files = sorted(project_dir.glob("requirements*.txt"))
    for req_file in req_files:
        try:
            for raw_line in req_file.read_text(encoding="utf-8").splitlines():
                parsed = parse_requirement_line(raw_line)
                if parsed:
                    register_pkg(parsed[0], parsed[1], scope="required")
        except Exception as e:
            print(f"Warning: Failed reading {req_file}: {e}", file=sys.stderr)

    # 2. Parse pyproject.toml if present
    pyproject = project_dir / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(encoding="utf-8")
            # Extract dependencies array items
            for m in re.finditer(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL):
                block = m.group(1)
                for item in re.findall(r'["\']([^"\']+)["\']', block):
                    parsed = parse_requirement_line(item)
                    if parsed:
                        register_pkg(parsed[0], parsed[1], scope="required")
        except Exception as e:
            print(f"Warning: Failed reading {pyproject}: {e}", file=sys.stderr)

    # 3. Expand transitive dependencies from installed metadata & known crypto trees
    direct_keys = list(discovered.keys())
    for norm_pkg in direct_keys:
        # Check importlib.metadata.requires if installed
        try:
            reqs = importlib.metadata.requires(norm_pkg) or []
            for req_str in reqs:
                if "extra ==" in req_str or "extra==" in req_str:
                    continue
                parsed = parse_requirement_line(req_str)
                if parsed:
                    register_pkg(parsed[0], parsed[1], scope="transitive")
        except importlib.metadata.PackageNotFoundError:
            pass

        # Also check known transitive dependencies for auth/crypto/http packages
        if norm_pkg in KNOWN_TRANSITIVE_DEPS:
            for trans_name, trans_ver in KNOWN_TRANSITIVE_DEPS[norm_pkg]:
                register_pkg(trans_name, trans_ver, scope="transitive")
                trans_norm = normalize_pypi_name(trans_name)
                if trans_norm in KNOWN_TRANSITIVE_DEPS:
                    for sub_name, sub_ver in KNOWN_TRANSITIVE_DEPS[trans_norm]:
                        register_pkg(sub_name, sub_ver, scope="transitive")

    return list(discovered.values())


def enrich_sbom(sbom_path: Path, project_dir: Path = Path(".")):
    """Merge discovered Python dependencies into CycloneDX SBOM."""
    py_deps = discover_python_dependencies(project_dir)
    if not py_deps:
        print("No Python dependencies discovered in project manifests.")
        return

    sbom_path.parent.mkdir(parents=True, exist_ok=True)

    if sbom_path.exists():
        try:
            with open(sbom_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    else:
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:python-runtime-dependencies",
            "version": 1,
            "metadata": {
                "component": {
                    "name": project_dir.resolve().name,
                    "type": "application",
                }
            },
            "components": [],
        }

    # Filter out bogus runner workflow file paths that lack a PURL
    raw_components = data.get("components", [])
    cleaned_components = []
    for c in raw_components:
        c_name = str(c.get("name") or "")
        c_purl = str(c.get("purl") or "")
        c_type = str(c.get("type") or "")
        if not c_purl and (c_type == "file" or c_name.startswith("/") or c_name.endswith((".yml", ".yaml"))):
            continue
        cleaned_components.append(c)

    data["components"] = cleaned_components
    existing_purls = {c.get("purl") for c in cleaned_components if c.get("purl")}
    existing_names = {normalize_pypi_name(c.get("name", "")) for c in cleaned_components if c.get("name")}

    added = 0
    for dep in sorted(py_deps, key=lambda d: d["name"]):
        if dep["purl"] not in existing_purls and dep["name"] not in existing_names:
            cleaned_components.append(dep)
            existing_purls.add(dep["purl"])
            existing_names.add(dep["name"])
            added += 1

    with open(sbom_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(
        f"✅ Enriched SBOM ({sbom_path}) with {added} Python dependencies "
        f"(Total SBOM components: {len(cleaned_components)})"
    )


def main():
    target_path = Path("oss/sbom.cyclonedx.json")
    project_dir = Path(".")
    if len(sys.argv) > 1:
        target_path = Path(sys.argv[1])
    if len(sys.argv) > 2:
        project_dir = Path(sys.argv[2])
    enrich_sbom(target_path, project_dir)


if __name__ == "__main__":
    main()
