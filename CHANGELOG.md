# Change Log

## v1.3.0 (2020-09-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX)

This release brings newly updated mappings to the [Malware Behavior Catalog version 2.0](https://github.com/MBCProject/mbc-markdown), many enhancements to the IDA Pro plugin, [flare-capa on PyPI](https://pypi.org/project/flare-capa/), a bunch of bug fixes to improve feature extraction, and four new rules. We received contributions from eleven reverse engineers, including five new ones:

  - @dzbeck
  - @recvfrom
  - @toomanybananas
  - @cclauss 
  - @adamprescott91 
  
Download a standalone binary below and checkout the readme [here on GitHub](https://github.com/fireeye/capa/). Report issues on our [issue tracker](https://github.com/fireeye/capa/issues) and contribute new rules at [capa-rules](https://github.com/fireeye/capa-rules/).

### Key changes to IDA Plugin

The IDA Pro integration is now distributed as a real plugin, instead of a script. This enables a few things:

  - keyboard shortcuts and file menu integration
  - updates distributed PyPI/`pip install --upgrade` without touching your `%IDADIR%`
  - generally doing thing the "right way"

How to get this new version? Its easy: download [capa_plugin_ida.py](https://raw.githubusercontent.com/fireeye/capa/master/capa/ida/plugin/capa_plugin_ida.py) to your plugins directory and update your capa installation (incidentally, this is a good opportunity to migrate to `pip install flare-capa` instead of git checkouts). Now you should see it in the `Edit>Plugins>capa explorer` menu. Please open an issue in this repository if you notice anything weird.

![image](https://user-images.githubusercontent.com/156560/92410275-d986b700-f100-11ea-9f93-efc83c2b7097.png)
 
### New features

  - ida plugin: now a real plugin, not a script @mike-hunhoff 
  - core: distributed via PyPI as [flare-capa](https://pypi.org/project/flare-capa/) @williballenthin 
  - features: enable automatic A/W handling for imports @williballenthin @Ana06 #246 
  - ida plugin: persist rules directory setting via [ida-settings](https://github.com/williballenthin/ida-settings) @williballenthin #268
  - ida plugin: add search bar to results view @williballenthin #285

### New rules

  - compiled with py2exe @re-fox
  - resolve path using msvcrt @re-fox 
  - decompress data using QuickLZ @edeca
  - encrypt data using sosemanuk @recvfrom 

### Bug fixes

  - rule: reduce FP in DNS resolution @toomanybananas
  - engine: report correct strings matched via regex @williballenthin #262 
  - formatter: correctly format descriptions in two-line syntax @williballenthin @recvfrom #263 
  - viv: better extract offsets from SibOper operands @williballenthin @edeca #276 
  - import-to-ida: fix import error @cclauss 

### Changes

  - rules: update meta mapping to MBC 2.0! @dzbeck
  - render: don't display rules that are also matched by other rules @williballenthin @Ana06 #224
  - ida plugin: simplify tabs, removing summary and adding detail to results view @williballenthin #286  

### Raw diffs

  - [capa v1.2.0...v1.3.0](https://github.com/fireeye/capa/compare/v1.2.0...v1.3.0)
  - [capa-rules v1.2.0...v1.3.0](https://github.com/fireeye/capa-rules/compare/v1.2.0...v1.3.0)

## v1.2.0 (2020-08-31)

This release brings UI enhancements, especially for the IDA Pro plugin, 
investment towards py3 support,
fixes some bugs identified by the community, 
and 46 (!) new rules.
We received contributions from ten reverse engineers, including five new ones:

  - @agithubuserlol
  - @recvfrom
  - @D4nch3n
  - @edeca
  - @winniepe 
  
Download a standalone binary below and checkout the readme [here on GitHub](https://github.com/fireeye/capa/).
Report issues on our [issue tracker](https://github.com/fireeye/capa/issues)
and contribute new rules at [capa-rules](https://github.com/fireeye/capa-rules/).
 
### New features

  - ida plugin: display arch flavors @mike-hunhoff
  - ida plugin: display block descriptions @mike-hunhoff
  - ida backend: extract features from nested pointers @mike-hunhoff
  - main: show more progress output @williballenthin
  - core: pin dependency versions #258 @recvfrom

### New rules
  - bypass UAC via AppInfo ALPC @agithubuserlol
  - bypass UAC via token manipulation @agithubuserlol
  - check for sandbox and av modules @re-fox
  - check for sandbox username @re-fox
  - check if process is running under wine @re-fox
  - validate credit card number using luhn algorithm @re-fox
  - validate credit card number using luhn algorithm with no lookup table @re-fox
  - hash data using FNV @edeca @mr-tz
  - link many functions at runtime @mr-tz
  - reference public RSA key @mr-tz
  - packed with ASPack @williballenthin
  - delete internet cache @mike-hunhoff
  - enumerate internet cache @mike-hunhoff
  - send ICMP echo request @mike-hunhoff
  - check for debugger via API @mike-hunhoff
  - check for hardware breakpoints @mike-hunhoff
  - check for kernel debugger via shared user data structure @mike-hunhoff
  - check for protected handle exception @mike-hunhoff
  - check for software breakpoints @mike-hunhoff
  - check for trap flag exception @mike-hunhoff
  - check for unexpected memory writes @mike-hunhoff
  - check process job object @mike-hunhoff
  - reference anti-VM strings targeting Parallels @mike-hunhoff
  - reference anti-VM strings targeting Qemu @mike-hunhoff
  - reference anti-VM strings targeting VirtualBox @mike-hunhoff
  - reference anti-VM strings targeting VirtualPC @mike-hunhoff
  - reference anti-VM strings targeting VMWare @mike-hunhoff
  - reference anti-VM strings targeting Xen @mike-hunhoff
  - reference analysis tools strings @mike-hunhoff
  - reference WMI statements @mike-hunhoff
  - get number of processor cores @mike-hunhoff
  - get number of processors @mike-hunhoff
  - enumerate disk properties @mike-hunhoff
  - get disk size @mike-hunhoff
  - get process heap flags @mike-hunhoff
  - get process heap force flags @mike-hunhoff
  - get Explorer PID @mike-hunhoff
  - delay execution @mike-hunhoff
  - check for process debug object @mike-hunhoff
  - check license value @mike-hunhoff
  - check ProcessDebugFlags @mike-hunhoff
  - check ProcessDebugPort @mike-hunhoff
  - check SystemKernelDebuggerInformation @mike-hunhoff
  - check thread yield allowed @mike-hunhoff
  - enumerate system firmware tables @mike-hunhoff
  - get system firmware table @mike-hunhoff
  - hide thread from debugger @mike-hunhoff

### Bug fixes

  - ida backend: extract unmapped immediate number features @mike-hunhoff
  - ida backend: fix stack cookie check #257 @mike-hunhoff
  - viv backend: better extract gs segment access @williballenthin
  - core: enable counting of string features #241 @D4nch3n @williballenthin
  - core: enable descriptions on feature with arch flavors @mike-hunhoff
  - core: update git links for non-SSH access #259 @recvfrom

### Changes

  - ida plugin: better default display showing first level nesting @winniepe
  - remove unused `characteristic(switch)` feature @ana06
  - prepare testing infrastructure for multiple backends/py3 @williballenthin
  - ci: zip build artifacts @ana06
  - ci: build all supported python versions @ana06
  - code style and formatting @mr-tz

### Raw diffs

  - [capa v1.1.0...v1.2.0](https://github.com/fireeye/capa/compare/v1.1.0...v1.2.0)
  - [capa-rules v1.1.0...v1.2.0](https://github.com/fireeye/capa-rules/compare/v1.1.0...v1.2.0)

## v1.1.0 (2020-08-05)

This release brings new rule format updates, such as adding `offset/x32` and negative offsets,
fixes some bugs identified by the community, and 28 (!) new rules.
We received contributions from eight reverse engineers, including four new ones:

  - @re-fox
  - @psifertex
  - @bitsofbinary
  - @threathive
  
Download a standalone binary below and checkout the readme [here on GitHub](https://github.com/fireeye/capa/). Report issues on our [issue tracker](https://github.com/fireeye/capa/issues) and contribute new rules at [capa-rules](https://github.com/fireeye/capa-rules/).
  
### New features

  - import: add Binary Ninja import script #205 #207 @psifertex
  - rules: offsets can be negative #197 #208 @williballenthin
  - rules: enable descriptions for statement nodes #194 #209 @Ana06
  - rules: add arch flavors to number and offset features #210 #216 @williballenthin
  - render: show SHA1/SHA256 in default report #164 @threathive
  - tests: add tests for IDA Pro backend #202 @williballenthin
  
### New rules

  - check for unmoving mouse cursor @BitsOfBinary
  - check mutex and exit @re-fox
  - parse credit card information @re-fox
  - read ini file @re-fox
  - validate credit card number with luhn algorithm @re-fox
  - change the wallpaper @re-fox
  - acquire debug privileges @williballenthin
  - import public key @williballenthin
  - terminate process by name @williballenthin
  - encrypt data using DES @re-fox
  - encrypt data using DES via WinAPI @re-fox
  - hash data using sha1 via x86 extensions @re-fox
  - hash data using sha256 via x86 extensions @re-fox
  - capture network configuration via ipconfig @re-fox
  - hash data via WinCrypt @mike-hunhoff
  - get file attributes @mike-hunhoff
  - allocate thread local storage @mike-hunhoff
  - get thread local storage value @mike-hunhoff
  - set thread local storage @mike-hunhoff
  - get session integrity level @mike-hunhoff
  - add file to cabinet file @mike-hunhoff
  - flush cabinet file @mike-hunhoff
  - open cabinet file @mike-hunhoff
  - gather firefox profile information @re-fox
  - encrypt data using skipjack @re-fox
  - encrypt data using camellia @re-fox
  - hash data using tiger @re-fox
  - encrypt data using blowfish @re-fox
  - encrypt data using twofish @re-fox

### Bug fixes

  - linter: fix exception when examples is `None` @Ana06
  - linter: fix suggested recommendations via templating @williballenthin
  - render: fix exception when rendering counts @williballenthin
  - render: fix render of negative offsets @williballenthin
  - extractor: fix segmentation violation from vivisect @williballenthin
  - main: fix crash when .viv cannot be saved #168 @secshoggoth @williballenthin
  - main: fix shellcode .viv save path @williballenthin

### Changes

  - doc: explain how to bypass gatekeeper on macOS @psifertex
  - doc: explain supported linux distributions @Ana06
  - doc: explain submodule update with --init @psifertex
  - main: improve program help output @mr-tz
  - main: disable progress when run in quiet mode @mr-tz
  - main: assert supported IDA versions @mr-tz
  - extractor: better identify nested pointers to strings @williballenthin
  - setup: specify vivisect download url @Ana06
  - setup: pin vivisect version @williballenthin
  - setup: bump vivisect dependency version @williballenthin
  - setup: set Python project name to `flare-capa` @williballenthin
  - ci: run tests and linter via Github Actions @Ana06
  - hooks: run style checkers and hide stashed output @Ana06
  - linter: ignore period in rule filename @williballenthin
  - linter: warn on nursery rule with no changes needed @williballenthin

### Raw diffs

  - [capa v1.0.0...v1.1.0](https://github.com/fireeye/capa/compare/v1.0.0...v1.1.0)
  - [capa-rules v1.0.0...v1.1.0](https://github.com/fireeye/capa-rules/compare/v1.0.0...v1.1.0)
