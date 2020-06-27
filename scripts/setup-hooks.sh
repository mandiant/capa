#!/usr/bin/env bash

set -e
set -u
set -o pipefail

GIT_DIR=`git rev-parse --show-toplevel`
cd $GIT_DIR

# hooks may exist already (e.g. git-lfs configuration)
# If the `.git/hooks/$arg` file doesn't exist it, initialize with `#!/bin/sh`
# After that append `scripts/hooks/$arg` and ensure they can be run
create_hook() {
  if [[ ! -e .git/hooks/$1 ]]; then
    echo "#!/bin/sh" > ".git/hooks/$1"
  fi
  cat scripts/hooks/$1 >> ".git/hooks/$1"
  chmod +x .git/hooks/$1
}

echo '\n#### Copying hooks into .git/hooks'
create_hook 'post-commit'
create_hook 'pre-push'
