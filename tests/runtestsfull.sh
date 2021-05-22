#!/bin/bash
which bc > /dev/null 2> /dev/null
if [ "$?" -gt "0" ]; then
    echo "You must have bc installed to use the test rig."
    exit 1
fi

which jq > /dev/null 2> /dev/null
if [ "$?" -gt "0" ]; then
    echo "You must have jq installed to use the test rig."
    exit 1
fi


stat ../xd > /dev/null 2> /dev/null
if [ "$?" -gt "0" ]; then
    echo "You must have built xd to use the test rig."
    echo "Use cd ..; make; cd tests"
    exit 1
fi

COUNT=`ls *.test | wc -l`
echo "RUNNING $COUNT TESTS..."
COUNTER=1
ALLPASS=1
for f in `ls *.test`
do
    TEST="`cat $f`"
    ../xd $TEST
    RESULT1="`../xd $TEST | jq empty 2>&1 | wc -c`"
    cat $f | ../xd -
    RESULT2="`cat $f | ../xd - | jq empty 2>&1 | wc -c`"
    ../xd $f
    RESULT3="`../xd $f | jq empty 2>&1 | wc -c`"
    RESULT="`echo $RESULT1 + $RESULT2 + $RESULT3 | bc`"
    if [ "$RESULT" -eq "0" ]; then
        echo "TEST $COUNTER/$COUNT :: PASS :: $f"
    else
        echo "TEST $COUNTER/$COUNT :: FAIL :: $f"
        echo "      $RESULT"
        ALLPASS=0
    fi
    COUNTER="`echo 1+$COUNTER | bc`"
done
if [ "$ALLPASS" -eq "1" ]; then
    echo "ALL TESTS PASSED"
else
    echo "NOT ALL TESTS PASSED"
fi
