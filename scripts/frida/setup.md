# Android Frida Environment Setup

## Emulator Setup

### Option A - Fully Automated 
emulator_creator.py will:
- Create an Android emulator (API 28, Google APIs)
- Download and install frida-server (17.2.15)
- Configure environment

### Option B: Manual Setup
Create your own emulator manually:

#### 1. Create and start emulator
For example, using Android Studio:
- Device: Pixel 4 XL
- System: API 29, Google APIs
Note: If you are on an Apple Silicon Mac, use the ARM64-v8a image; on Intel/AMD, use an x86_64 image.
 
#### 2. Enable root access
```bash
# Switch to root mode
adb root

# Should return "root" if properly rooted
adb shell whoami  
```
Note: Google APIs images allow root access by default. If you selected Google Play images, you'll need additional rooting tools like rootAVD.

#### 3. Install frida-server
Download appropriate frida-server(for the emulator’s CPU architecture) from [Frida releases](https://github.com/frida/frida/releases), and install:

```bash
# Install to device
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
```

#### 4. Start frida-server
```bash
adb shell "/data/local/tmp/frida-server &"
```

## Start Analysis
Once setup is complete:
```bash
python main.py --package com.example.app --apk /path/to/app.apk 
```