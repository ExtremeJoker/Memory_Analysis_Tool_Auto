#!/bin/bash
#Timer to record the script's run - Test internal FUNCTION library
#SECONDS=0

function genstats() {
	#General Statistics (Docu)
	echo "Time of Analysis: $SECONDS seconds "
	sleep 2
	
	FILES=$(find "$UOUTPUT" -type f | wc -l)
	echo "Number of found files: $FILES "
	sleep 2

    if [[ -n "$HASH_SUMMARY" ]]; then
        echo ""
        echo "NOTE:Credential/hash pattern scan was run during this session:"
        echo "$HASH_SUMMARY"
    fi
}


		
