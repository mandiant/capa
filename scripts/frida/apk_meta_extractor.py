import json
import hashlib
import argparse
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime


def calculate_hashes(apk_path):
    try:
        with open(apk_path, "rb") as f:
            content = f.read()

        md5 = hashlib.md5(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()

        print("Calculated hashes Successfully")
        return {"md5": md5, "sha1": sha1, "sha256": sha256}

    except Exception as e:
        print(f"Failed to calculate hashes: {e}")
        return None


def calculate_hashes_via_adb(package_name):
    """Use ADB to get APK and calculate hashes"""
    try:
        # Get APK path from device
        result = subprocess.run(
            ["adb", "shell", "pm", "path", package_name], capture_output=True, text=True, check=True
        )

        # The 'package:' prefix is consistent across all Android versions
        # and is a standard part of the pm path command's output.
        if not result.stdout.startswith("package:"):
            print(f"[-] Package {package_name} not found on device")
            return None

        apk_path = result.stdout.strip()[8:]

        # Then pull APK to temporary local file and calculate hashes
        with tempfile.TemporaryDirectory() as temp_dir:
            local_apk_path = Path(temp_dir) / f"{package_name}.apk"

            subprocess.run(["adb", "pull", apk_path, str(local_apk_path)], check=True)

            hashes = calculate_hashes(local_apk_path)
            return hashes

    except subprocess.CalledProcessError:
        print(f"Package '{package_name}' not found on device")
        return None
    except Exception as e:
        print(f"Error getting APK from device: {e}")
        return None


def save_apk_meta(hashes, package_name):
    """Save hash in JSON file for hook_builder.py to use"""
    try:
        script_dir = Path(__file__).parent
        temp_dir = script_dir / ".temp"
        temp_dir.mkdir(exist_ok=True)
        output_file = temp_dir / "apk_meta.json"

        apk_meta = {"package_name": package_name, "hashes": hashes, "timestamp": datetime.now().isoformat()}

        with open(output_file, "w") as f:
            json.dump(apk_meta, f, indent=2)

        print(f"APK meta saved to: {output_file}")
        return output_file

    except Exception as e:
        print(f"Failed to save APK meta: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Extract APK meta including hashes")
    parser.add_argument("--package", required=True, help="Android package name")
    parser.add_argument("--apk", type=Path, help="Local APK file path (optional)")

    args = parser.parse_args()

    try:
        # Get hashes from either local file or device
        if args.apk:
            # User provided APK file path
            if not args.apk.exists():
                print(f"APK file not found: {args.apk}")
                return 1

            hashes = calculate_hashes(args.apk)
        else:
            # Get APK from device using ADB
            hashes = calculate_hashes_via_adb(args.package)

        if not hashes:
            return 1

        if not save_apk_meta(hashes, args.package):
            return 1

        return 0

    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    main()
