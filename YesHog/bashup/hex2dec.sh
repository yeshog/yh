[ "x$1" == "" ] && echo "hex2dec <hex>" && exit 1
t=/tmp/tmp.hex2dec
p=$(dirname "${BASH_SOURCE[0]}")
echo "ibase=16">$t
n=$1
d=$(echo -n "$n"|sed -e 's/ //g' -e 's/0x//g'|tr 'a-z' 'A-Z')
k=$(echo $d|bc -l $p/funcs.bc $t)
echo $k
rm $t

