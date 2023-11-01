echo Filter 1: "s/%bdevq%/set/g; s/%grfxdh%/ /g; s/%mbbzmk%/=/g; s/%mbbzmk%/=/g; s/%xeegh%/\//g; s/%jeuudks%/a/g; s/%rbiky%/c/g; s/%wzirk%/m/g; s/%naikpbo%/d/g; s/%ltevposie%/e/g; s/%uqcqswo%/x/g; s/%zvipzis%/i/g; s/%kquqjy%/t/g; s/%kmgnxdhqb%/ /g"
echo "s/%bdevq%/set/g; s/%grfxdh%/ /g; s/%mbbzmk%/=/g; s/%mbbzmk%/=/g; s/%xeegh%/\//g; s/%jeuudks%/a/g; s/%rbiky%/c/g; s/%wzirk%/m/g; s/%naikpbo%/d/g; s/%ltevposie%/e/g; s/%uqcqswo%/x/g; s/%zvipzis%/i/g; s/%kquqjy%/t/g; s/%kmgnxdhqb%/ /g" > filter1.txt
sed "s/%bdevq%/set/g; s/%grfxdh%/ /g; s/%mbbzmk%/=/g; s/%mbbzmk%/=/g; s/%xeegh%/\//g; s/%jeuudks%/a/g; s/%rbiky%/c/g; s/%wzirk%/m/g; s/%naikpbo%/d/g; s/%ltevposie%/e/g; s/%uqcqswo%/x/g; s/%zvipzis%/i/g; s/%kquqjy%/t/g; s/%kmgnxdhqb%/ /g" batchfuscation.bat > b_pass1.bat
cat b_pass1.bat|grep ^"set /a" > pass_2_sets.tmp

filter=""

while IFS= read -r line
do
  var=`echo $line | cut -d" " -f3| cut -d"=" -f1`
  arg1=`echo $line | cut -d" " -f3| cut -d"=" -f2`
  arg2=`echo $line | cut -d" " -f5`
  res=`echo $arg1 % $arg2 | bc`
  char=`awk -v char=$res 'BEGIN { printf "%c\n", char; exit }'`

  filter=$filter"; s/%$var%/$char/g"
done < pass_2_sets.tmp

echo Filter 2: $filter
echo $filter > filter2.txt
cat b_pass1.bat| sed "$filter" > b_pass2.bat
cat b_pass2.bat|grep "cmd /c " -A1 | grep -v ^"-" > pass_3_sets.tmp

filter=""
while read -r one; do
    read -r two
    char=`echo $one|cut -d" " -f4`
    var=`echo $two|cut -d" " -f2|cut -d"%" -f1`
    var=`echo $var|sed "s/=//g"`
    filter=$filter"; s/%$var%/$char/g"
done < pass_3_sets.tmp

echo Filter3: $filter
echo $filter > filter3.txt
cat b_pass2.bat|sed "$filter" > b_pass3.bat

cat b_pass3.bat | grep "flag_character" > pass_4_sets.tmp
flag=""
for i in `seq 1 38`; do
    line=`grep flag_character$i= pass_4_sets.tmp|cut -d"=" -f2`
    flag=$flag$line
done

echo The flag is: $flag
