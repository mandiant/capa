fields=("load FLIRT" "viv analyze" "match functions" "match file" "find capabilities");

echo -n "|         |";
for T in "${fields[@]}"; do
    printf ' %-17s |' "$T";
done
echo "";
 
echo -n "|---------|";
for T in "${fields[@]}"; do
    echo -n '-------------------|';
done
echo "";

for rev in "$@"; do

    echo -n "| $rev |";
    for T in "${fields[@]}"; do
        V1=$(cat scripts/perf/capa-$rev-PMA0101.txt | grep "$T" | sed -e "s/^.*$T: //g");
        V2=$(cat scripts/perf/capa-$rev-k32.txt | grep "$T" | sed -e "s/^.*$T: //g");
        printf ' %-17s |' "$V1/$V2";
    done
    echo "";
done
