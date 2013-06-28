#set -x
export BC_LINE_LENGTH=1024
BF=/tmp/bcf$$
X=0
Y=0
A=0
PRM1=3
PRM2=5

function cleanup() {
	rm $BF
}

function check() {
	[ $? == 0 ] || (echo "Error" && cleanup && exit 1)
}

function createbcfuncs() {

cat >$BF<<EOF
define int(x)   { auto os; os=scale; scale=0; x/=1; scale=os; return(x) }
define floor(x) { auto xx; xx=int(x); if(xx>x)xx-=1; return(xx) }
define mod(x,y) { if (y == 0) return x else return x - y * floor(x / y) }
EOF

l=$(cat $BF|wc -l)
[ "$l" == "3" ] || (echo "Expected 3 lines in $BF got $l" && cleanup && exit 1)

}

function extended_gcd() {
	x="0"
	y="1"
	lastx="1"
	lasty="0"
	a=$1
	b=$2
	while 	[ $b != "0" ]
	do
		temp=$b
		q=$(echo "floor($a/$b)"|bc -l $BF)
		b=$(echo "mod($a,$b)"|bc -l $BF)
		a=$temp

		temp=$x
		x=$(echo "$lastx-($q*$x)"|bc -l)
		lastx=$temp

		temp=$y
		y=$(echo "$lasty-($q*$y)"|bc -l)
		lasty=$temp
	done
	X=$lastx
	Y=$lasty
	A=$a
}

[ -f genprime ] || (echo "genprime absent" && exit 1)
createbcfuncs
[ -n "$1" ] && PRM1=$1
[ -n "$2" ] && PRM2=$2

## Start the tests

extended_gcd $PRM1 $PRM2
echo "Result X=$X, Y=$Y, A=$A"
cleanup
