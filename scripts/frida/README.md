# Frida Analysis for capa
This tool uses Frida to monitor Android applications and generates behavioral JSONL data that capa can analyze to identify program capabilities.

Frida enables dynamic analysis by watching what API calls an Android app makes when it runs. This tool instruments Android apps with Frida, recording hooked API call information. The recorded data is formatted as JSONL for capa to analyze using its capability detection rules.

## Prerequisites

**Android Development Environment**

Download Android Studio from [Android Studio Website](https://developer.android.com/studio).

Install these SDK components in Android Studio → Settings → Languages & Frameworks → Android SDK → SDK Tools: 
`Android SDK Command-line Tools`, `Android Emulator`, `Android SDK Platform-Tools`, and `Android SDK Build-Tools`.

Default SDK locations:
- macOS: `~/Library/Android/sdk`
- Linux: `~/Android/Sdk`
- Windows: `~\AppData\Local\Android\Sdk`

**Analysis Tool**

Download capa from [capa repo](https://github.com/mandiant/capa) to analyze the behavioral data output.

**Dependencies**

```bash
# Python dependencies needed
pip install frida==17.2.15 frida-tools jinja2

# Install Node.js npm for frida-compile
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

Press Ctrl+D to stop Frida monitoring, results are saved to `frida_outputs/` folder. Then you can run capa on the output files to analyze capabilities.

**What the automation does:**
Creates an configed emulator
Extracts APK metadata and hashes
Generates monitoring script from API specifications
Executes Frida analysis with compiled script
Retrieves results for capa

## Manual Workflow (if you want)

For users who prefer step-by-step control, see [Manual Steps Guide](manual_steps.md).
