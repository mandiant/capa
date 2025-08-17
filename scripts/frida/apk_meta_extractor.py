import json
import hashlib
import argparse
import tempfile
import subprocess
from pathlib import Path


def load_apk_metadata():
    """Load APK meta information from saved file"""
    base_dir = Path(__file__).resolve().parent
    meta_file = base_dir / ".temp" / "apk_meta.json"

    if not meta_file.exists():
        raise ValueError(f"APK meta file not found: {meta_file}")

    with open(meta_file, "r") as f:
        meta_data = json.load(f)

    return meta_data


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
    result = subprocess.run(
        ["adb", "shell", "pm", "path", package_name],
        capture_output=True,
        text=True,
        check=True,
    )

    # The 'package:' prefix is consistent across all Android versions
    # and is a standard part of the pm path command's output.
    if not result.stdout or not result.stdout.startswith("package:"):
        raise ValueError(f"Package {package_name} not found on device")

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

    script_dir = Path(__file__).parent
    # TODO: could be saved in /tmp.
    temp_dir = script_dir / ".temp"

    temp_dir.mkdir(exist_ok=True)
    output_file = temp_dir / "apk_meta.json"

    apk_meta = {"package_name": package_name, "hashes": hashes}

    with open(output_file, "w") as f:
        json.dump(apk_meta, f, indent=2)

    print(f"APK meta saved to: {output_file}")
    return output_file


def extract_apk_metadata(package_name, apk_path=None):
    """Entry point: Extract and save APK metadata, including hashes and package_name"""
    # Get hashes from either local file or device
    if apk_path:
        if not Path(apk_path).exists():
            raise ValueError(f"APK file not found: {apk_path}")
        hashes = calculate_hashes(apk_path)
    else:
        # From device via ADB
        hashes = calculate_hashes_via_adb(package_name)

    metadata_file = save_apk_metadata(package_name, hashes)
    return metadata_file


def main():
    parser = argparse.ArgumentParser(description="Extract APK meta including hashes")
    parser.add_argument("--package", required=True, help="Android package name")
    parser.add_argument("--apk", type=Path, help="Local APK file path (optional)")

    args = parser.parse_args()

    try:
        extract_apk_metadata(args.package, args.apk)
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    main()
