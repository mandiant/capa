#!/usr/bin/env bash
# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

set -euo pipefail

GIT_DIR=$(git rev-parse --show-toplevel);
cd "$GIT_DIR";

# hooks may exist already (e.g. git-lfs configuration)
# If the `.git/hooks/$arg` file doesn't exist it, initialize with `#!/usr/bin/env bash`
# After that append `scripts/hooks/$arg` and ensure they can be run
create_hook() {
  if [[ ! -e .git/hooks/$1 ]]; then
    echo "#!/usr/bin/env bash" > ".git/hooks/$1";
  fi
  echo "scripts/ci.sh ${2:-}" >> ".git/hooks/$1";
  chmod +x .git/hooks/"$1";
}

printf 'Adding scripts/ci.sh to .git/hooks/';
create_hook 'pre-commit' 'no_tests';
create_hook 'pre-push';
