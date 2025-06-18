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
var filePath = "/data/local/tmp/frida_output/api_calls.jsonl";
// "/data/data/com.example.fridatestjavaapp/files/api_calls.json";
// "/data/local/tmp/frida_output/frida_" + timestamp + ".json";

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

function writeJavaApiCall(apiData) {
    var record = {
        "id": recordId++,
        "api": {
            "java_api": apiData
        }
    };

    if (writeRecord(record)) {
        console.log("[+] API call written: " + apiData.api_name);
    }
}

function collectBasicInfo() {
    allMetadata.process_id = Process.id;
    allMetadata.arch = Process.arch;
    allMetadata.platform = Process.platform;
    console.log("[+] Basic info collected");
}

collectBasicInfo();

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

    var call_id = 0;

    // Currently recordApiCall only captures basic: process_id, thread_id, call_id, api_name
    // TODO: Will implement arguments and return_value parameters after testing current basic structure.
    function recordApiCall(apiName) {
        var apiCallRecord = {
            "process_id": Process.id,
            "thread_id": Process.getCurrentThreadId(),
            "call_id": call_id++,
            "api_name": apiName
        };
        
        writeJavaApiCall(apiCallRecord);
    }
    
    function debugLog(apiName, args, returnValue) {
        var logEntry = {
            "type": "api",
            "name": apiName,
            "args": args || {},
            "return_value": returnValue,
            "timestamp": Date.now(),
            "process_id": Process.id,
            "thread_id": Process.getCurrentThreadId(),
            "call_id": call_id,
        };
        console.log("CAPA_API_LOG_ENTRY:" + JSON.stringify(logEntry));
    }
    
    // Monitor java.io.File
    try {
        var File = Java.use("java.io.File");
        
        File.$init.overload('java.lang.String').implementation = function(path) {
            recordApiCall("java.io.File.<init>");
            debugLog("java.io.File.<init>", {"path": path});
            return this.$init(path);
        };
        
        File.delete.implementation = function() {
            var path = this.getAbsolutePath();
            var result = this.delete();
            recordApiCall("java.io.File.delete");
            debugLog("java.io.File.delete", {"path": path}, result);
            return result;
        };
        
        console.log("[+] File operations hooked");
        
    } catch(e) {
        console.log("[ERROR] File hook failed: " + e);
    }

    // Monitor FileInputStream
    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            var path = file.getAbsolutePath();
            recordApiCall("java.io.FileInputStream.<init>");
            debugLog("java.io.FileInputStream.<init>", {"path": path});
            return this.$init(file);
        };
        
        FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
            recordApiCall("java.io.FileInputStream.<init>");
            debugLog("java.io.FileInputStream.<init>", {"path": path});
            return this.$init(path);
        };
        
        console.log("[+] FileInputStream hooked");
        
    } catch(e) {
        console.log("[ERROR] FileInputStream hook failed: " + e);
    }

    // Monitor FileOutputStream
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        
        FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
            recordApiCall("java.io.FileOutputStream.<init>");
            debugLog("java.io.FileOutputStream.<init>", {"path": path});
            return this.$init(path);
        };
        
        FileOutputStream.write.overload('[B').implementation = function(bytes) {
            recordApiCall("java.io.FileOutputStream.write");
            debugLog("java.io.FileOutputStream.write", {"bytes": bytes.length});
            return this.write(bytes);
        };
        
        console.log("[+] FileOutputStream hooked");
        
    } catch(e) {
        console.log("[ERROR] FileOutputStream hook failed: " + e);
    }

});