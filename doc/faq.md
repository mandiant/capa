# Frequently Asked Questions
## Why does capa trigger my Antivirus? Is the tool safe to use?
The purpose of `capa` is to analyse the capabilities of a potentially malicious application or file. To achieve this, it needs to include portions of the data it is designed to detect as a basis for comparison.
The release version of capa comes with embedded rules designed to detect common malware functionality. These rules possess similar features to malware and may trigger alerts.
Additionally, Antivirus and Endpoint Detection and Response (EDR) products may alert on the way capa is packaged using PyInstaller.

## How can I ensure that capa is a benign program?
We recommend downloading releases only from this repository's Release page. Alternatively, you can build capa yourself or use other Python installation methods. This project is open-source, ensuring transparency for everyone involved.
For additional peace of mind, you can utilize VirusTotal to analyze unknown files against numerous antivirus products, sandboxes, and other analysis tools. It's worth noting that capa itself operates within VirusTotal.

### Understanding VirusTotal output
VirusTotal tests files against a large number of Antivirus engines and sandboxes. There's often little insight into Antivirus detections, but you can further inspect dynamic analysis results produced by sandboxes.
These details can be used to double-check alerts and understand detections.
