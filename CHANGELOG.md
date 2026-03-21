# Change Log

## master (unreleased)

### New Features

- ghidra: support PyGhidra @mike-hunhoff #2788
- vmray: extract number features from whitelisted void_ptr parameters (hKey, hKeyRoot) @adeboyedn #2835

### Breaking Changes

### New Rules (23)

- nursery/run-as-nodejs-native-module mehunhoff@google.com
- nursery/inject-shellcode-using-thread-pool-work-insertion-with-tp_io still@teamt5.org
- nursery/inject-shellcode-using-thread-pool-work-insertion-with-tp_timer still@teamt5.org
- nursery/inject-shellcode-using-thread-pool-work-insertion-with-tp_work still@teamt5.org
- data-manipulation/encryption/hc-256/encrypt-data-using-hc-256 wballenthin@hex-rays.com
- anti-analysis/anti-llm/terminate-anthropic-session-via-magic-strings wballenthin@hex-rays.com
- nursery/access-aws-credentials maximemorin@google.com
- nursery/access-cloudflare-credentials maximemorin@google.com
- nursery/access-docker-credentials maximemorin@google.com
- nursery/access-gcp-credentials maximemorin@google.com
- nursery/access-kubernetes-credentials maximemorin@google.com
- nursery/enumerate-aws-cloudformation maximemorin@google.com
- nursery/enumerate-aws-cloudtrail maximemorin@google.com
- nursery/enumerate-aws-direct-connect maximemorin@google.com
- nursery/enumerate-aws-ec2 maximemorin@google.com
- nursery/enumerate-aws-iam maximemorin@google.com
- nursery/enumerate-aws-s3 maximemorin@google.com
- nursery/enumerate-aws-support-cases maximemorin@google.com
- persistence/registry/persist-via-shellserviceobjectdelayload-registry-key xpzhxhm@gmail.com
- nursery/get-http-response-date @cosmoworker
- host-interaction/process/create/create-process-in-dotnet moritz.raabe@mandiant.com social.tarang@gmail.com
- nursery/read-file-in-dotnet moritz.raabe@mandiant.com anushka.virgaonkar@mandiant.com
- nursery/write-file-in-dotnet william.ballenthin@mandiant.com anushka.virgaonkar@mandiant.com
-

### Bug Fixes
- main: suggest --os flag in unsupported OS error message to help users override ELF OS detection @devs6186 #2577
- render: escape sample-controlled strings before passing to Rich to prevent MarkupError @devs6186 #2699
- rules: handle empty or invalid YAML documents gracefully in `Rule.from_yaml` and `get_rules` @devs6186 #2900
- Fixed insecure deserialization vulnerability in YAML loading @0x1622 (#2770)
- loader: gracefully handle ELF files with unsupported architectures kamranulhaq2002@gmail.com #2800
- loader: handle SegmentationViolation for malformed ELF files @kami922 #2799
- lint: disable rule caching during linting @Maijin #2817
- vmray: skip processes with invalid PID or missing filename @EclipseAditya #2807
- features: fix Regex.get_value_str() returning escaped pattern instead of raw regex @EclipseAditya #1909
- render: use default styling for dynamic -vv API/call details so they are easier to see @devs6186 #1865
- loader: handle struct.error from dnfile and show clear CorruptFile message @devs6186 #2442
- address: fix TypeError when sorting locations containing mixed address types @devs6186 #2195
- loader: skip PE files with unrealistically large section virtual sizes to prevent resource exhaustion @devs6186 #1989
- engine/render: fix unbounded range sentinel precedence so `count(...): N or more` uses explicit `((1 << 64) - 1)` @blenbot #2936
- cache: support *BSD @williballenthin @res2500 #2949

### capa Explorer Web
- webui: fix 404 for "View rule in capa-rules" by using encodeURIComponent for rule name in URL @devs6186 #2482
- webui: show error when JSON does not follow expected result document schema; suggest reanalyzing for VT URLs @devs6186 #2363
- webui: fix global search to match feature types (match, regex, api, …) @devs6186 #2349

### capa Explorer IDA Pro plugin

### Performance

- perf: eliminate O(n²) tuple growth and reduce per-match overhead @devs6186 #2890

### Development

- doc: document that default output shows top-level matches only; -v/-vv show nested matches @devs6186 #1410
- doc: fix typo in usage.md, add documentation links to README @devs6186 #2274
- doc: add table comparing ways to consume capa output (CLI, IDA, Ghidra, dynamic sandbox, web) @devs6186 #2273
- binja: add mypy config for top-level binaryninja module to fix mypy issues @devs6186 #2399
- rules: pre-filter extracted bytes with 4-byte prefixes for faster candidate selection instead of linear scan #2128
- ci: deprecate macos-13 runner and use Python v3.13 for testing @mike-hunhoff #2777
- ci: pin pip-audit action SHAs and update to v1.1.0 @kami922 #1131
- ci: implement pip caching across all workflows @Deetya #2944
