#!/bin/bash

# unset variables are errors
set -o nounset;
# any failed commands are errors
set -o errexit;

# current_directory is the path to the directory containing this script.
# ref: https://stackoverflow.com/a/4774063/87207
readonly CD="$( cd "$(dirname "$0")" ; pwd -P )"

panic() {
	echo "[erro]: $@" >&2;
	exit 1;
}

info() {
	echo "[info]: $@" >&2;
}

verbose=false;
debug() {
	if "$verbose"; then
		echo "[debu]: $@" >&2;
	fi
}

if [ "$(git status | grep "modified: " | grep -v "rules" | grep -v "tests/data")" ]; then
    panic "modified content";
fi

rev=$(git rev-parse --short HEAD);
info "rev: $rev";

mkdir -p "$CD/perf/";

info "analyzing PMA 01-01.dll...";

pma_out=$(
    py-spy record \
    -o "$CD/perf/capa-$rev-PMA0101.svg" \
    -- python -m capa.main \
       -d \
       "$CD/../tests/data/Practical Malware Analysis Lab 01-01.dll_" \
       2>&1 || true);

echo "$pma_out" | grep "perf:" | sed -e "s/^.*perf: /perf: /g" | tee "$CD/perf/capa-$rev-PMA0101.txt";
 
info "analyzing kernel32.dll...";
k32_out=$(
    py-spy record \
    -o "$CD/perf/capa-$rev-k32.svg" \
    -- python -m capa.main \
       -d \
       "$CD/../tests/data/kernel32.dll_" \
       2>&1 || true);

echo "$k32_out" | grep "perf:" | sed -e "s/^.*perf: /perf: /g" | tee "$CD/perf/capa-$rev-k32.txt";

bash "$CD/render-time-profile.sh" "$rev";

info "done.";
