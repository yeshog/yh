[ $# -ne 1 ] && echo "undebug.sh <c source file>" && exit 1
[ -f $1 ] || (echo "undebug.sh file [$1] not found" && exit 1)
[ ${1##*.} == "c" ] && echo "Removing debug statements from $1"
cat $1|sed '/.*debug.*/,/.*end debug*/d'|sed '/^[ \t]*$/d' >xxx.c
mkdir -p debug
fcopy=${1%.*}`date +'__%Y_%m_%d_%H_%M_%S'`.c
echo "making copy at debug/$fcopy"
cp $1 debug/$fcopy
mv xxx.c $1



