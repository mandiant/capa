# Android Frida Environment Setup

## Emulator Setup

### Option A - Fully Automated 
emulator_creator.py will:
- Create a rooted emulator with API 28
- Download and setup frida-server-17.2.15-android-arch

### Option B: Manual Setup
Create your own emulator Manually:

#### 1. Create AVD in Android Studio
```bash
## Using Android Studio GUI
Tools → Device Manager → + Create Virtual Device
- Device: Pixel 4 XL
- System: API 29, Android 10, Google APIs
- Arch: arm64
```

#### 2. Launch with root access
```bash
# Launch emulator with root capabilities
emulator -avd emulator_name -writable-system

Or use ? rootAVD?...
```

### 3. Install and prestart frida server
```bash
adb shell getprop ro.product.cpu.abilist

https://github.com/frida/frida/releases/tag/17.2.15
# Download appropriate frida-server (example for arm64)
wget https://github.com/frida/frida/releases/download/17.2.15/frida-server-17.2.15-android-arm64.xz
xz -d frida-server-17.2.15-android-arm64.xz  
mv frida-server-17.2.15-android-arm64 frida-server

# Push to device
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Start frida server for frida analysis
adb shell "/data/local/tmp/frida-server &"
```

## Start Analysis
Once setup is complete:
```bash
python main.py --package com.example.app --apk /path/to/app.apk 
```