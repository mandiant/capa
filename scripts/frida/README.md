# Frida Dynamic Analysis

This guide shows how to generate Frida hooks and analyze Android app API calls with capa.

## Prerequisites

### 1. Download Android Studio
Download from: https://developer.android.com/studio

**Required SDK components for auto-emulator creation** 
(install via Settings → Languages & Frameworks → Android SDK → SDK Tools):
- Android SDK Command-line Tools (for sdkmanager & avdmanager)
- Android Emulator (for emulator command)
- Android SDK Platform-Tools (for adb)
- Android SDK Build-Tools (for aapt)

**Automatic mode users**: Just install Android Studio to default location. Our tool handles PATH temporarily during each execution.
**Manual mode users**: Add Android SDK tools to your system PATH permanently

**Default SDK locations:**
- macOS: `~/Library/Android/sdk`
- Linux: `~/Android/Sdk`
- Windows: `~\AppData\Local\Android\Sdk`

### 2. Install Dependencies
```bash
# jinja2 pydantic could be added to requirements.txt later

# Python packages
pip install frida==17.2.15 frida-tools jinja2 pydantic
pip install capa[frida]

# Node.js (for frida-compile)
brew install node  # macOS
# sudo apt install nodejs npm  # Linux
# Download from nodejs.org for Windows
```

### (Optional) Create emulator and start frida-server
We can auto-create an rooted emulator with frida-server for you.
But you can manually setup your own emulator/device.
For more details, see our [manual setup guide](setup.md) and
[Frida Server + Rooted Emulator](https://docs.google.com/document/d/1WpPRcdtnPYdOn4n7Wl3aghbZUv2wmefiuaf2WDIR5Pw/edit?tab=t.0#heading=h.sqgvzr4xgg42)

## Usage
### Automated Analysis (Recommended)
```bash
# Complete pipeline - creates emulator if needed
# To start the AVDs auto-created, open your Android Studio
# Tools → Device Manager → find 'frida-emulator' and start it"

# Scenario 1: Package already on device
python main.py --package com.example.app

# Scenario 2: Only APK file (auto install APK and extracts package name)
python main.py --apk /path/to/app.apk

# Required at least one of `--package com.example.app` or `--apk /path/to/app.apk`
# --package: Android package name (e.g. com.example.app)
# --apk: Local APK file path (Auto install APK and auto extracts package name)

# Additional options:
# --apis: JSON filename containing APIs (default: frida_apis.json)
# --script: Output script filename (default: frida_monitor.ts)  
# --output: JSONL output filename in emulator that you wanna create after monitoring (default: api_calls.jsonl)
```
The tool will:
Auto-create emulator if no device connected
Install APK to device automatically
Extract package name from APK if only APK provided
Generate and run Frida monitoring script
Retrieve results for capa analysis

### Manual Steps (if you want)

### Step 0: Device Preparation
```bash
# Create output directory with full permissions
adb shell su -c "mkdir -p /data/local/tmp/frida_outputs"
adb shell su -c "chmod -R 777 /data/local/tmp/frida_outputs"

# Disable SELinux enforcement (resets on reboot)
adb shell su -c "setenforce 0"

# Start Frida server on device
adb shell su -c "/data/local/tmp/frida-server &"
```
```bash
# Navigate to the frida dir
cd scripts/frida/
```

### Step 1: Install APK
```bash
# If APK not already on device:
adb install -r /path/to/app.apk
```

### Step 2: Extract APK Metadata 
```bash
# Extract APK metadata (package name + hashes) and save to temp file
# Required: At least one of --package or --apk

# Auto-extract package name
python apk_meta_extractor.py --apk /path/to/app.apk
# Get APK from device
python apk_meta_extractor.py --package com.example.app          
```

### Step 3: Generate Frida Monitoring Script
```bash
# Generate monitoring script
python hook_builder.py
# Options:
# --apis: JSON filename containing APIs (default: frida_apis.json)
# --script: Output script filename (default: frida_monitor.ts)  
# --output: JSONL output filename in emulator that you wanna create after monitoring (default: api_calls.jsonl)
```

### Step 4(Optional): JavaScript bundle via frida-compile
The generated TypeScript script could be compiled with frida-compile:
automation part contain this, because Frida 17.x bridge...
```bash
mkdir -p agent
cd agent
frida-create -t agent
npm install
npm install frida-java-bridge
cd ..

# Prepare script for compilation (for example Java bridge import), add this to script: 
import Java from "frida-java-bridge"; 

# Compile TypeScript to JavaScript bundle
frida-compile path_to_your_script -o agent/compiled_bundle.js
```

### Step 5: Run Dynamic Analysis

```bash
# Launch Rootbeer app with Frida monitoring
# With frida-compile step, use compiled bundle:
frida -U -f com.scottyab.rootbeer.sample -l agent/compiled_bundle.js

# Otherwise, use:
frida -U -f com.scottyab.rootbeer.sample -l frida_scripts/frida_monitor.ts

# For other apps, use their package name:
# frida -U -f com.example.app -l frida_scripts/frida_monitor.ts

# Let the app run and perform the behaviors you want to analyze
# Type `exit` and Press `Ctrl+C` to stop monitoring
```

**Notes:**
- File Permission Conflicts
Root Cause: Android apps create files with their UID ownership. App A cannot overwrite files created by App B.
- Solution 1: Delete this file before next analysis
- Solution 2: Change to a new filename for {jsonl_filename} in frida_monitor.ts, you can directly use --output command line:
var filePath = "/data/local/tmp/frida_outputs/{{jsonl_filename}}";

### Step 6: Retrieve Analysis Data

```bash
# (Check if file exits)
adb shell su -c "ls -la /data/local/tmp/frida_outputs/"

adb root
# Using adb pull
adb pull /data/local/tmp/frida_outputs/api_calls.jsonl ./frida_outputs/api_calls.jsonl
```

## Analyze with capa
```bash
# Navigate back to capa root directory
cd ../../

# Activate your capa environment
source ~/capa-env/bin/activate 

# Using your custom Frida rules (for development/testing)
python capa/main.py -r scripts/frida/test_rules/ -d scripts/frida/frida_outputs/api_calls.jsonl

# Using this after integrated
capa api_calls.jsonl
```

### Folder Components
- **main.py**: Complete automation pipeline

**Directories:**
- **/frida_apis/*.json**: Contains API JSON files
- **/frida_templates/**: Jinja2 templates for script generation
- **/frida_scripts/*.ts**: Generated executable scripts (output)
- **/agent/**: frida-compile environment and compiled bundles
- **/frida_outputs/*.jsonl**: outputs that need capa to anlaysis


!!!
Put these here for now

- **Rooted Android emulator with Frida server running**  
[Frida Server + Rooted Emulator](https://docs.google.com/document/d/1WpPRcdtnPYdOn4n7Wl3aghbZUv2wmefiuaf2WDIR5Pw/edit?tab=t.0#heading=h.sqgvzr4xgg42)

- **Python virtual environment with capa installed**  
[capa install page](https://github.com/mandiant/capa/blob/master/doc/installation.md)

- **Target app installed on emulator**  
Example: RootBeer sample app from Google Play Store, or build from [Rootbeer Github](https://github.com/scottyab/rootbeer?tab=readme-ov-file) (Rootbeer GitHub version is newer)