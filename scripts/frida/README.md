# Frida Analysis for capa

This tool uses Frida to monitor Android applications and generates behavioral JSONL data that capa can analyze to detect malicious capabilities.

Frida enables dynamic analysis by watching what API calls an Android app makes when it runs. This tool instruments Android apps with Frida, recording their API call information. The recorded data is formatted as JSONL for capa to analyze using behavioral detection rules.

## Prerequisites

**Android Development Environment**

Download Android Studio from [Android Studio Website](https://developer.android.com/studio).

Install these SDK components in Android Studio → Settings → Languages & Frameworks → Android SDK → SDK Tools: 
`Android SDK Command-line Tools`, `Android Emulator`, `Android SDK Platform-Tools`, and `Android SDK Build-Tools`.

Default SDK locations:
- macOS: `~/Library/Android/sdk`
- Linux: `~/Android/Sdk`
- Windows: `~\AppData\Local\Android\Sdk`

**Dependencies**

Install capa from [capa Github](https://github.com/mandiant/capa).

Install required tools:

```bash
# Python packages
pip install frida==17.2.15 frida-tools jinja2

# Install Node.js for npm 
# macOS: `brew install node`
# Linux: `sudo apt install nodejs npm`
# Windows: Download from [nodejs.org](https://nodejs.org)
```

## Quick start

The tool creates an Android emulator automatically if you don't have one connected.

```bash
# Scenario 1: Analyze app already on device
python main.py --package com.example.app

# Scenario 2: Install APK and analyze
python main.py --apk /path/to/app.apk

# Additional customized options:
# --apis: JSON filename containing APIs (default: frida_apis.json)
# --script: Output script filename (default: frida_monitor.ts)  
# --output: JSONL output filename on device (default: api_calls.jsonl)
```

Press Ctrl+D to stop Frida monitoring, then analyze with capa:

```bash
capa frida_outputs/api_calls.jsonl
```

## Manual workflow

You can run individual steps manually for debugging or customization.

**Device setup**

The tool auto-creates a configured emulator (Pixel 4 XL, API 29, Google APIs) with frida-server 17.2.15, named 'frida-emulator'. Start it through Android Studio → Tools → Device Manager.

For manual device setup, see [Device setup](setup.md).

```bash
# Install APK if needed
adb install -r /path/to/app.apk

# Navigate to frida directory
cd scripts/frida/
```

**Step 1: Extract APK Metadata**

Extract application metadata including cryptographic hashes and package information. This helps capa identify the sample and correlate findings.

```bash
# Requires at least one of --package or --apk
# Extract from device APK
python apk_meta_extractor.py --package com.example.app
# Or from local APK file
python apk_meta_extractor.py --apk /path/to/app.apk
```

**Step 2: Generate Frida Monitoring Script**

Generate a customized monitoring script based on your API configuration:

```bash
python hook_builder.py

# Additional customized options:
# --apis: JSON filename containing APIs (default: frida_apis.json)
# --script: Output script filename (default: frida_monitor.ts)  
# --output: JSONL output filename on device (default: api_calls.jsonl)
```

The tool uses standardized API JSON files with templates in `/frida_templates/hook_templates` to generate hooks. The complete generated TypeScript script saves to `/frida_scripts`.

**Step 3: JavaScript Bundle Compilation (Optional)**

The generated TypeScript can be compiled with frida-compile for better compatibility:

```bash
mkdir -p agent
cd agent
frida-create -t agent
npm install
npm install frida-java-bridge
cd ..

# Compile TypeScript to JavaScript bundle
frida-compile path_to_your_script -o agent/compiled_bundle.js
```

This step is included in the automation because Frida 17.x requires specific bridge imports when using the Python API, though the command line interface still works as before.

**Step 4: Run Dynamic Analysis**

Launch the application with Frida monitoring:

```bash
# Using compiled bundle (recommended)
frida -U -f com.example.app -l agent/compiled_bundle.js

# Using TypeScript directly
frida -U -f com.example.app -l frida_scripts/frida_monitor.ts
```

As the app runs, the script hooks API calls and records them in JSONL format with calling context and parameters.
Let the app run and perform behaviors you want to analyze. Type `exit` then press Ctrl+C to stop monitoring.

**Step 5: Retrieve Analysis Output**

Collect the recorded behavioral data to local:

```bash
# (Check if output file exists)
adb shell "ls -la /data/local/tmp/frida_outputs/"

# Pull analysis data from device
adb pull /data/local/tmp/frida_outputs/api_calls.jsonl ./frida_outputs/api_calls.jsonl
```

## Analyze with capa

The JSONL file contains a chronological record of API calls behavior that capa can process with behavioral rules. Process with capa:

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

## Known Issues

**Note:** Some emulators (e.g., Magisk-rooted) uses `adb shell su -c "command"`, while others don't support the `-c` parameter. So modify commands accordingly, or use `adb shell CLI` instead.

**Note:** If you encounter Frida errors `[ERROR] Failed to open file:`, this is usually a permission issue. There are two main situations:
run `adb shell "setenforce 0"` to disable SELinux again, since in some  cases, it will be reset by system.
And also happens because android apps create files with their own UID ownership, causing permission conflicts between different apps. To resolve this, either delete existing output file or use different filenames with the `--output` option.



### Folder Components
- **/frida_apis/*.json**: Contains API JSON files
- **/frida_templates/**: Jinja2 templates for script generation
- **/frida_scripts/*.ts**: Generated executable scripts (output)
- **/agent/**: frida-compile environment and compiled bundles
- **/frida_outputs/*.jsonl**: outputs for capa analysis
