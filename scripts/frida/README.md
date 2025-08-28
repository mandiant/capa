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

**What the automation does:**
Creates an configed emulator
Extracts APK metadata and hashes
Generates monitoring script from API specifications
Executes Frida analysis with compiled script 
Retrieves results for capa 

## Manual Workflow

For users who prefer step-by-step control, see [Manual Steps Guide](manual_steps.md).
