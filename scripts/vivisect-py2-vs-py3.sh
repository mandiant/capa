#!/usr/bin/env bash

int() {
  int=$(bc <<< "scale=0; ($1 + 0.5)/1")
}

export TIMEFORMAT='%3R'
threshold_time=90
threshold_py3_time=60 # Do not warn if it doesn't take at least 1 minute to run
rm tests/data/*.viv 2>/dev/null
mkdir results
for file in tests/data/*
do
  file=$(printf %q "$file") # Handle names with white spaces
  file_name=$(basename $file)
  echo $file_name

  rm "$file.viv" 2>/dev/null
  py3_time=$(sh -c "time python3 scripts/show-features.py $file >> results/p3-$file_name.out 2>/dev/null" 2>&1)
  rm "$file.viv" 2>/dev/null
  py2_time=$(sh -c "time python2 scripts/show-features.py $file >> results/p2-$file_name.out 2>/dev/null" 2>&1)

  int $py3_time
  if (($int > $threshold_py3_time))
  then
    percentage=$(bc <<< "scale=3; $py2_time/$py3_time*100 + 0.5")
    int $percentage
    if (($int < $threshold_py3_time))
    then
      echo -n "  SLOWER ($percentage): "
    fi
  fi
  echo "  PY2($py2_time) PY3($py3_time)"
done

threshold_features=98
counter=0
average=0
results_for() {
  py3=$(cat "results/p3-$file_name.out" | grep "$1" | wc -l)
  py2=$(cat "results/p2-$file_name.out" | grep "$1" | wc -l)
  if (($py2 > 0))
  then
    percentage=$(bc <<< "scale=2; 100*$py3/$py2")
    average=$(bc <<< "scale=2; $percentage + $average")
    count=$(($count + 1))
    int $percentage
    if (($int < $threshold_features))
    then
      echo -e "$1: py2($py2) py3($py3) $percentage% - $file_name"
    fi
  fi
}

rm tests/data/*.viv 2>/dev/null
echo -e '\nRESULTS:'
for file in tests/data/*
do
  file_name=$(basename $file)
  if test -f "results/p2-$file_name.out"; then
    results_for 'insn'
    results_for 'file'
    results_for 'func'
    results_for 'bb'
  fi
done

average=$(bc <<< "scale=2; $average/$count")
echo "TOTAL: $average"
