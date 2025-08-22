import os
import sys
import time
import shutil
import platform
import tempfile
import subprocess
from pathlib import Path

FRIDA_VERSION = "17.2.15"


def get_system_architecture():
    """
    Detect system architecture for emulator and frida-server arch
    Returns: tuple: (avd_arch, frida_arch)
    """
    machine = platform.machine().lower()
    print(f"Detected system: {platform.machine()}")

    if machine in ["arm64", "aarch64"]:
        return "arm64-v8a", "android-arm64"
    elif machine in ["x86_64", "amd64"]:
        return "x86_64", "android-x86_64"
    else:
        print("Unsupported architecture. Manual setup required.")
        return None


def setup_android_sdk_path():
    """Add Android SDK tools to PATH to enable command-line usage:
    - platform-tools: adb command
    - emulator: emulator command
    - cmdline-tools: sdkmanager & avdmanager
    """
    system = platform.system()

    if system == "Darwin":  # macOS
        android_home = os.path.expanduser("~/Library/Android/sdk")
        path_separator = ":"
    elif system == "Linux":
        android_home = os.path.expanduser("~/Android/Sdk")
        path_separator = ":"
    else:  # Windows
        android_home = os.path.expanduser(r"~\AppData\Local\Android\Sdk")
        path_separator = ";"

    os.environ["ANDROID_HOME"] = android_home

    # Add Android tools to PATH
    if system == "Windows":
        paths_to_add = [
            f"{android_home}\\platform-tools",
            f"{android_home}\\emulator",
            f"{android_home}\\cmdline-tools\\latest\\bin",
        ]
    else:
        paths_to_add = [
            f"{android_home}/platform-tools",
            f"{android_home}/emulator",
            f"{android_home}/cmdline-tools/latest/bin",
        ]

    current_path = os.environ.get("PATH", "")
    for path in paths_to_add:
        if path not in current_path:
            current_path = f"{current_path}{path_separator}{path}"

    os.environ["PATH"] = current_path
    print("Add Android tools to PATH")


def create_emulator(avd_arch):
    """Create Android emulator, system Image and AVD"""
    avd_name = "frida-emulator"
    system_image = f"system-images;android-28;google_apis;{avd_arch}"

    # Check if AVD already exists
    result = subprocess.run(["avdmanager", "list", "avd", "-c"], capture_output=True, text=True)
    if avd_name in result.stdout:
        response = input(f"AVD '{avd_name}' exists. Delete and recreate? (y/n): ").lower()
        if response == "y":
            subprocess.run(["avdmanager", "delete", "avd", "-n", avd_name], check=True)
        else:
            print("Using existing AVD")
            return avd_name

    print("Installing system image...")
    result = subprocess.run(["sdkmanager", system_image], capture_output=True, text=True)
    if result.returncode != 0:
        print("Failed to install system image")
        return None

    print("Creating emulator...")
    result = subprocess.run(
        ["avdmanager", "create", "avd", "-n", avd_name, "-k", system_image, "-d", "pixel_4_xl"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("Failed to create emulator")
        return None

    print(f"emulator '{avd_name}' created ")
    return avd_name


def start_emulator(avd_name):
    """Start emulator and wait for boot"""
    print("Starting emulator...")
    subprocess.Popen(
        ["emulator", "-avd", avd_name, "-writable-system"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    print("Waiting for boot...")
    subprocess.run(["adb", "wait-for-device"], check=True)

    # Wait for boot completion
    while True:
        result = subprocess.run(["adb", "shell", "getprop", "sys.boot_completed"], capture_output=True, text=True)
        if result.stdout.strip() == "1":
            break
        time.sleep(3)

    subprocess.run(["adb", "root"], capture_output=True)

    # Setup device
    subprocess.run(["adb", "shell", "mkdir", "-p", "/data/local/tmp/frida_outputs"], capture_output=True)
    subprocess.run(["adb", "shell", "chmod", "777", "/data/local/tmp/frida_outputs"], capture_output=True)
    subprocess.run(["adb", "shell", "setenforce", "0"], capture_output=True)


def check_frida_server_installed():
    """Check if frida-server is already installed"""
    try:
        result = subprocess.run(["adb", "shell", "test", "-f", "/data/local/tmp/frida-server"], capture_output=True)
        return result.returncode == 0
    except:
        return False


def download_frida_server(frida_arch):
    """Download frida-server"""
    temp_dir = Path(tempfile.gettempdir())
    extracted_file = temp_dir / f"frida-server-{FRIDA_VERSION}-{frida_arch}"
    archive_file = temp_dir / f"frida-server-{FRIDA_VERSION}-{frida_arch}.xz"

    if extracted_file.exists():
        print("Using cached frida-server")
        return str(extracted_file)

    print(f"Downloading frida-server for {frida_arch}...")
    url = (
        f"https://github.com/frida/frida/releases/download/{FRIDA_VERSION}/frida-server-{FRIDA_VERSION}-{frida_arch}.xz"
    )

    if shutil.which("curl"):
        subprocess.run(["curl", "-L", "-o", str(archive_file), url], cwd=temp_dir, check=True)
    elif shutil.which("wget"):
        subprocess.run(["wget", "-q", url], cwd=temp_dir, check=True)
    else:
        print("Neither curl nor wget found")
        print(f"Manual download required: {url}")
        return None

    # Extract .xz
    subprocess.run(["xz", "-d", str(archive_file)], check=True)
    return str(extracted_file)


def setup_frida_server(frida_arch):
    """Setup frida-server on device"""
    frida_server_path = download_frida_server(frida_arch)
    if not frida_server_path:
        return False

    print("Installing frida-server to device...")
    subprocess.run(["adb", "root"], check=True)
    subprocess.run(["adb", "push", frida_server_path, "/data/local/tmp/frida-server"], check=True)
    subprocess.run(["adb", "shell", "chmod", "755", "/data/local/tmp/frida-server"], check=True)
    return True


def start_frida_server():
    """Start frida-server on device"""
    # In case, kill existing and start new
    subprocess.run(["adb", "shell", "killall", "frida-server"], capture_output=True)
    subprocess.Popen(
        ["adb", "shell", "/data/local/tmp/frida-server", "&"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    print("frida-server started")


def create_frida_emulator():
    # First Step: Get Arch first, AVD and frida-server needs it
    arch = get_system_architecture()
    if not arch:
        return False
    avd_arch, frida_arch = arch

    # Next Step:
    setup_android_sdk_path()

    # Next Step:
    avd_name = create_emulator(avd_arch)
    if not avd_name:
        return False

    # Next Step:
    start_emulator(avd_name)

    # Next Step:
    if not check_frida_server_installed():
        if not setup_frida_server(frida_arch):
            return False

    # Next Step:
    start_frida_server()

    print("Emulator setup complete!")

    return True


def main():
    if create_frida_emulator():
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
