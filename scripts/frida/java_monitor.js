/**
 * Capa Frida Java API Monitor
 * This script monitors Java API calls and outputs data in JSON format
 * 
 * How to use it:
 * frida -U -f com.example.app -l java_monitor.js
 */

// TODO: Add Thread.backtrace to get position to ensure api call happens on target place
// TODO: Auto create script with api list
// TODO: Selective api list get from rules

console.log("[+] Capa Frida Java Monitor initializing...");

// TODO: Should we use timestamp in filename for multiple runs? and let user specify output path via command line?
var timestamp = Date.now(); 
var filePath = "/data/local/tmp/frida_output/api_calls_0718.jsonl";
// "/data/data/com.example.fridatestjavaapp/files/api_calls.json";
// "/data/local/tmp/frida_output/frida_" + timestamp + ".json";

var javaHooksPath = "/data/local/tmp/frida_output/java_hooks.js"; 
var nativeHooksPath = "/data/local/tmp/frida_output/native_hooks.js";

var outputFile = null;
var recordId = 0;
var allMetadata = {};

try {
    outputFile = new File(filePath, "w");
} catch (e) {
    console.log("[ERROR] Failed to open file: " + e);
}

function writeRecord(record) {
    if (outputFile) {
        outputFile.write(JSON.stringify(record) + '\n');
        outputFile.flush();
        return true;
    }
    return false;
}

function writeMetadata() {
    var record = {
        "id": recordId++,
        "metadata": allMetadata
    };

    if (writeRecord(record)) {
        console.log("[+] Metadata written")
    }
}

function collectBasicInfo() {
    allMetadata.process_id = Process.id;
    allMetadata.arch = Process.arch;
    allMetadata.platform = Process.platform;
    console.log("[+] Basic info collected");
}

collectBasicInfo();

var call_id = 0;

function recordApiCall(apiName, argumentsList, apiType) {
    var apiCallRecord = {
        "process_id": Process.id,
        "thread_id": Process.getCurrentThreadId(),
        "call_id": call_id++,
        "api_name": apiName,
        "arguments": argumentsList || []
    };
    
    var record = {
        "id": recordId++,
        "api": {}
    };
    
    record.api[apiType] = apiCallRecord;
    
    if (writeRecord(record)) {
        console.log("[+] " + apiType + " call written: " + apiName);
    }
}

function processValue(arg) {
    if (arg === null || typeof arg === 'undefined') {
        return null;
    }
    
    if (typeof arg === 'string' || typeof arg === 'number' || typeof arg === 'boolean') {
        return arg;
    }

    // Handle Frida-wrapped Java objects
    if (typeof arg === 'object' && arg.$className) {
        return arg.toString();
    }

    // Handle arrays and other objects with toString()
    // Note: JavaScript objects may become "[object Object]",
    // beacause non-overridden Object.prototype.toString() returns type info, not content
    return arg.toString();
}

function parseNativeValue(arg, argType) {
    if (arg.isNull()) {
        return null;
    }
    
    switch (argType) {
        case 'int':
            return arg.toInt32();
        case 'uint':
            return arg.toUInt32();
        case 'bool':
            return arg.toInt32() !== 0;

        case 'char*':
        case 'const char*':
            try {
                var str = arg.readUtf8String();
                return str !== null ? str : arg.toString();
            } catch (e) {
                return arg.toString();
            }
        
        default:
            return arg.toString();
    }
}

function loadHookFile(hookPath, hookType) {
    try {
        var hooksContent = File.readAllText(hookPath);
        eval(hooksContent);
    } catch (e) {
        console.log("[ERROR] " + hookType + " hooks not available: " + e.message);
    }
}

Java.perform(function() {
    console.log("[+] Capa Frida Java Monitor started");

    // Debug found ActivityThread.currentApplication() available after 1 second, returns null otherwise
    // but this doesn't guarantee metadata will be written as first line in JSON.
    // Current approach can ensure each script reinjection maintains complete metadata without requiring device restart
    setTimeout(function() {
    
        var ActivityThread = Java.use("android.app.ActivityThread");
        var currentApp = ActivityThread.currentApplication();
        
        if (currentApp && currentApp.getPackageName) {
            allMetadata.package_name = currentApp.getPackageName().toString();
            console.log("[+] Package name: " + allMetadata.package_name);
        } else {
            console.log("[!] Could not get package name, using fallback");
            allMetadata.package_name = "unknown_package";
        }
        
        writeMetadata();
    }, 1000);

    loadHookFile(javaHooksPath, "Java");
    loadHookFile(nativeHooksPath, "Native");

});