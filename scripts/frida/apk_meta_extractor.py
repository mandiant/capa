import re
import sys
import json
import shutil
import hashlib
import logging
import argparse
import tempfile
import subprocess
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)


def load_apk_metadata():
    """Load APK meta information from saved file"""
    temp_dir = Path(tempfile.gettempdir()) / "capa_frida"
    meta_file = temp_dir / "apk_meta.json"

    if not meta_file.exists():
        raise FileNotFoundError(f"APK meta file not found: {meta_file}")

    with open(meta_file, "r") as f:
        meta_data = json.load(f)

    return meta_data


def extract_package_name_from_apk(apk_path: Path):
    """Use aapt command to extract package name from given APK file"""
    if not shutil.which("aapt"):
        raise FileNotFoundError("aapt tool not found. Please install Android SDK build-tools.")

    try:
        result = subprocess.run(["aapt", "d", "badging", str(apk_path)], capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to run aapt on APK: {e}")

    for line in result.stdout.splitlines():
        if line.startswith("package:"):
            match = re.search(r"name='([^']+)'", line)
            if match:
                return match.group(1)

    raise RuntimeError("Could not extract package name in APK file")


def calculate_hashes(apk_path):
    """Calculate MD5, SHA1, SHA256 hashes for APK file"""

    with open(apk_path, "rb") as f:
        content = f.read()

    md5 = hashlib.md5(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    sha256 = hashlib.sha256(content).hexdigest()

    return {"md5": md5, "sha1": sha1, "sha256": sha256}


def calculate_hashes_via_adb(package_name):
    """Use ADB to get APK and calculate hashes"""
    try:
        result = subprocess.run(
            ["adb", "shell", "pm", "path", package_name], capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        raise ValueError(f"Package '{package_name}' not found on device.") from e

    # The 'package:' prefix is consistent across all Android versions
    # and is a standard part of the pm path command's output.
    device_apk_path = result.stdout.strip()[8:]

    # Then pull APK to temporary local file and calculate hashes
    with tempfile.TemporaryDirectory() as temp_dir:
        local_apk_path = Path(temp_dir) / f"{package_name}.apk"
        subprocess.run(["adb", "pull", device_apk_path, str(local_apk_path)], capture_output=True, check=True)

        return calculate_hashes(local_apk_path)


def save_apk_metadata(package_name, hashes):
    """Save hash and package_name in JSON file for hook_builder.py"""
    if not package_name:
        raise ValueError("Package name cannot be empty")
    if not hashes:
        raise ValueError("Hashes cannot be empty")

    temp_dir = Path(tempfile.gettempdir()) / "capa_frida"
    temp_dir.mkdir(exist_ok=True)

    output_file = temp_dir / "apk_meta.json"

    apk_meta = {"package_name": package_name, "hashes": hashes}

    with open(output_file, "w") as f:
        json.dump(apk_meta, f, indent=2)

    logger.info(f"APK meta saved to: {output_file}")
    return output_file


def extract_apk_metadata(package_name=None, apk_path: Optional[Path] = None):
    """Entry point: Extract and save APK metadata, including hashes and package_name"""
    if not package_name and not apk_path:
        raise ValueError("Must provide either package_name or apk_path")

    if apk_path:
        if not apk_path.exists():
            raise FileNotFoundError(f"APK file not found: {apk_path}")

        extracted_package = extract_package_name_from_apk(apk_path)
        if package_name and extracted_package != package_name:
            raise ValueError(f"Package name mismatch: provided '{package_name}', APK contains '{extracted_package}'")

        package_name = extracted_package
        logger.info(f"Extract APK package_name: {package_name}")

        # Calculate hashes from local file
        hashes = calculate_hashes(apk_path)
    else:
        # Calculate hashes from device APK file
        hashes = calculate_hashes_via_adb(package_name)

    metadata_file = save_apk_metadata(package_name, hashes)
    return metadata_file, package_name


def main():
    parser = argparse.ArgumentParser(description="Extract APK meta including hashes")
    parser.add_argument("--package", default=None, help="Android package name")
    parser.add_argument("--apk", default=None, type=Path, help="Local APK file path (optional)")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    try:
        metadata_file, package_name = extract_apk_metadata(args.package, args.apk)
        return 0
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
