#!/usr/bin/env bash

# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

# Use a console with emojis support for a better experience
# Use venv to ensure that `python` calls the correct python version

# Stash uncommitted changes
MSG="pre-push-$(date +%s)";
git stash push -kum "$MSG" &>/dev/null ;
STASH_LIST=$(git stash list);
if [[ "$STASH_LIST" == *"$MSG"* ]]; then
  echo "Uncommitted changes stashed with message '$MSG', if you abort before they are restored run \`git stash pop\`";
fi

restore_stashed() {
  if [[ "$STASH_LIST" == *"$MSG"* ]]; then
    git stash pop --index &>/dev/null ;
    echo "Stashed changes '$MSG' restored";
  fi
}

# Run isort and print state
python -m isort --profile black --length-sort --line-width 120 -c . > isort-output.log 2>&1;
if [ $? == 0 ]; then
  echo 'isort succeeded!! 💖';
else
  echo 'isort FAILED! 😭';
  echo 'Check isort-output.log for details';
  restore_stashed;
  exit 1;
fi

# Run black and print state
python -m black -l 120 --check . > black-output.log 2>&1;
if [ $? == 0 ]; then
  echo 'black succeeded!! 💝';
else
  echo 'black FAILED! 😭';
  echo 'Check black-output.log for details';
  restore_stashed;
  exit 2;
fi

# Run rule linter and print state
python ./scripts/lint.py ./rules/ > rule-linter-output.log 2>&1;
if [ $? == 0 ]; then
  echo 'Rule linter succeeded!! 💘';
else
  echo 'Rule linter FAILED! 😭';
  echo 'Check rule-linter-output.log for details';
  restore_stashed;
  exit 3;
fi

# Run tests except if first argument is no_tests
if [ "$1" != 'no_tests' ]; then
  echo 'Running tests, please wait ⌛';
  python -m pytest tests/ --maxfail=1;
  if [ $? == 0 ]; then
    echo 'Tests succeed!! 🎉';
  else
    echo 'Tests FAILED! 😓';
    echo 'Run `pytest -v --cov=capa test/` if you need more details';
    restore_stashed;
    exit 4;
  fi
fi

restore_stashed;
echo 'SUCCEEDED 🎉🎉';

