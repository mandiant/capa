# Android Device Setup for Frida Analysis

This guide covers setting up Android devices for Frida dynamic analysis.

For manual setup or physical devices, ensure you have root access and a compatible Frida server. Version mismatches between Python Frida client and Android server cause connectivity problems - the tool uses Frida 17.2.15.


### 1. Create Android Emulator

1. Open Android Studio
2. Go to Tools → Device Manager → Create Virtual Device
3. Choose device definition (we use: Pixel 4 XL)
4. Choose system image (we use: API 29, Google APIs)
5. Create and run

**Architecture selection:**
- Apple Silicon Mac: ARM64 (arm64-v8a)
- Intel/AMD systems: x86_64
 
### 2. PATH Configuration

The main tool handles temporary PATH configuration during execution, but manual users should add Android SDK tools needed to your system PATH permanently. Otherwise you'll need to configure PATH each time you want to use these commands directly.
The main tool uses `platform-tools(for adb)`, `build-tools(for aapt)`, `emulator(for emulator)`, and `cmdline-tools(for sdkmanager & avdmanager)`.

### 3. Verify Root Access

Google APIs images provide root access by default. If you selected Google Play images, you'll need additional rooting tools like rootAVD and need a full cold boot to apply and persist root changes. Verify access by:

```bash
# Switch to superuser (root) privileges
adb root

# Should return "root" if properly rooted
adb shell whoami  
```

### 4. Install and start Frida Server

Download the appropriate version (matching your emulator CPU architecture) from [Frida releases](https://github.com/frida/frida/releases), unzip and rename it, then install:

```bash
# Check your device cpu type
adb shell getprop ro.product.cpu.abilist

# Install to device with proper permissions
adb push frida-server /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"

# Start frida-server, return port if start successfully 
adb shell "/data/local/tmp/frida-server &"
```

### 5. Prepare Device Environment

Prepare the device output environment with proper permissions. 

```bash
# Create output directory with full permissions
adb shell "mkdir -p /data/local/tmp/frida_outputs"
adb shell "chmod -R 777 /data/local/tmp/frida_outputs"

# Disable SELinux enforcement
adb shell "setenforce 0"
```
