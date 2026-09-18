#!/bin/bash
#Validate the file for which version of volatility can be used
function cfilevolver(){
	local vol2_path="./volatility_2.5_linux_x64"
	vol3_bin=""
	
	CFILE_VOL2="no"
	CFILE_VOL3="no"
	
	#Check for Vol3
	for candidate in "$(command -v vol 2>/dev/null)" "/usr/local/bin/vol" "/usr/bin/vol" "$HOME/.local/bin/vol"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
        vol3_bin="$candidate"
        break
    fi
	done

	if [[ -z "$vol3_bin" ]]; then
		echo "Volatility3 (vol) NOT found in system"
	else 
		echo "Volatility3 found: $vol3_bin"
		if "$vol3_bin" -f "$FNAME" windows.info >/dev/null 2>&1; then
			echo "Volatility3 appears compatible with this image"
			CFILE_VOL3="yes"
		else
			echo "Volatility3 was unable to identify this image"
		fi
	fi
	#Check for Vol2
	local vol2_output=""
	if [[ -x "$vol2_path" && -f "$vol2_path" ]]; then
		vol2_output=$("$vol2_path" -f "$FNAME" imageinfo 2>&1) 
	elif [[ -f "$vol2_path"/vol.py ]]; then
		if command -v python2 &>/dev/null; then
			vol2_output=$(python2 "$vol2_path/vol.py" -f "$FNAME" imageinfo 2>&1) 
		else
			echo "Volatility2 found but python2 is not installed - Unable to run"
		fi
	else
		echo "Volatility2 binary/script NOT found at $vol2_path"
	fi
	
	if echo "$vol2_output" | grep -q "Suggested Profile"; then
		echo "Volatility2 appears compatible with this image"
		CFILE_VOL2="yes"
	elif [[ -n "$vol2_output" ]]; then
		echo "Volatility2 UNABLE to identify this image"
	fi
	
	echo "===============SUMMARY==============="
	echo "Compatibility summary: Volatility2=$CFILE_VOL2 and Volatility3=$CFILE_VOL3"
	
	if [[ "$CFILE_VOL2" == "no" &&  "$CFILE_VOL3" == "no" ]]; then
		return 1
	fi
	return 0
}

function volchoice() {
	while true; do
		read -p  "Please state which version you would like to run [2 OR 3]: " VCHOICE #For functional library testing purposes ONLY
		
		if [[ "$VCHOICE" != "2" && "$VCHOICE" != "3" ]]; then
			local VREP
			read -rp "You have not entered a valid selection, would you like to try again?[Y/N]" VREP
			VREP="${VREP,,}"
			if [[ "$VREP" == "y" ]]; then
				continue
			else
				echo "Exiting version choice"
			fi
		fi
		
		if [[ "$VCHOICE" == "2" ]]; then
			./volatility_2.5_linux_x64 -f "$FNAME" imageinfo #Insert back after testing"$FNAME"
			read -p  "Please choose the suggested profile you would like to use: " PCHOICE
			volchoice2
			cd "$UOUTPUT" && zip -r volatility2.zip volatility2/
			echo "Volatility2 output zip completed"
			break
		elif [[ "$VCHOICE" == "3" ]]; then 
			volchoice3
			cd "$UOUTPUT" && zip -r volatility3.zip volatility3/
			echo "Volatility3 output zip completed"
			break
		fi
	done
}
						
function processinfo() {
	#Process information and store into file
	echo "==========PROCESS INFORMATION=========="
	./volatility_2.5_linux_x64 -f "$FNAME" --profile="$PCHOICE" pslist >vol_pslist_"${RUN_TIME}" #For functional library testing purposes ONLY. All scan Win2008SP1x86
	./volatility_2.5_linux_x64 -f "$FNAME" --profile="$PCHOICE"  psscan >vol_psscan_"${RUN_TIME}" #In case of hidden process, meant to track malicious
	mkdir -p "$UOUTPUT/volatility2/vol_pslist"
	mkdir -p "$UOUTPUT/volatility2/vol_psscan"
	mv vol_pslist_"${RUN_TIME}" "$UOUTPUT/volatility2/vol_pslist/"
	mv vol_psscan_"${RUN_TIME}" "$UOUTPUT/volatility2/vol_psscan/" 
	echo "==============COMPLETED==============="
}

function networkcon() {
	#Network Connections and display connection
	 echo "==========NETWORK CONNECTIONS========="
	 if echo "$PCHOICE" | grep -qiE "^winxp|^win2003"; then #This is for legacy situations
		./volatility_2.5_linux_x64 -f "$FNAME" --profile="$PCHOICE" connscan > "vol_connscan_${RUN_TIME}"
        mkdir -p "$UOUTPUT/volatility2/vol_connscan"
        mv "vol_connscan_${RUN_TIME}" "$UOUTPUT/volatility2/vol_connscan/"
     elif echo "$PCHOICE" | grep -qiE "^win"; then #This is for Vista OS and up
		./volatility_2.5_linux_x64 -f "$FNAME" --profile="$PCHOICE" netscan > "vol_netscan_${RUN_TIME}"
        mkdir -p "$UOUTPUT/volatility2/vol_netscan"
        mv "vol_netscan_${RUN_TIME}" "$UOUTPUT/volatility2/vol_netscan/"
    else
        echo "Profile '$PCHOICE' does not appear to be a Windows profile - netscan/connscan not applicable"
        return 1
    fi
    echo "==============COMPLETED==============="
}

function cmdcheck() {
	#Commands executed and display commands 
	echo "==========COMMANDS=========="
	local consoles_file="vol_consoles_${RUN_TIME}"
	local cmdscan_file="vol_cmdscan_${RUN_TIME}"
	
	./volatility_2.5_linux_x64 -f "$FNAME" --profile="$PCHOICE"  consoles > "$consoles_file"
	
	if [[ -s "$consoles_file" ]]; then
		mkdir -p "$UOUTPUT/volatility2/vol_consoles"
		mv "$consoles_file" "$UOUTPUT/volatility2/vol_consoles/"
	else
		echo "'consoles' returned nothing, falling back to cmdscan"
		rm -f "$consoles_file"
		./volatility_2.5_linux_x64 -f "$FNAME" --profile="$PCHOICE"  cmdscan > "$cmdscan_file"
		mkdir -p "$UOUTPUT/volatility2/vol_cmdscan"
		mv "$cmdscan_file" "$UOUTPUT/volatility2/vol_cmdscan/"
	fi
	
	./volatility_2.5_linux_x64 -f "$FNAME" --profile="$PCHOICE"  cmdline >vol_cmdline_"${RUN_TIME}"
	mkdir -p "$UOUTPUT/volatility2/vol_cmdline"
	mv vol_cmdline_"${RUN_TIME}" "$UOUTPUT/volatility2/vol_cmdline/"
	echo "==============COMPLETED==============="
}
	
function dllcheck() {
	#dllist dump
	 echo "==========Dllist=========="
	./volatility_2.5_linux_x64 -f "$FNAME" --profile="$PCHOICE"  dlllist >vol_dlllist_"${RUN_TIME}"
	mkdir -p "$UOUTPUT/volatility2/vol_dlllist"
	mv vol_dlllist_"${RUN_TIME}" "$UOUTPUT/volatility2/vol_dlllist/" 
	echo "==============Completed==============="
}

function hivechecks() {
	#Extract Reg info
	echo "==========HIVELIST=========="
	function hiveinfo() {
		./volatility_2.5_linux_x64 -f "$FNAME" --profile="$PCHOICE"  hivelist >vol_hivelist_"${RUN_TIME}"
	}
	#Extract hashes into file - Virtual addresses from list
	function hivehash() {
		local locsystem locsam locsecurity
		locsystem=$(cat "vol_hivelist_${RUN_TIME}" | grep -iE '\\SYSTEM$' | awk '{print $1}')
        locsam=$(cat "vol_hivelist_${RUN_TIME}" | grep -iE "\\SAM$" | awk '{print $1}')
        locsecurity=$(cat "vol_hivelist_${RUN_TIME}" | grep -iE "\\SECURITY$" | awk '{print $1}')
		
		./volatility_2.5_linux_x64 -f "$FNAME" --profile="$PCHOICE"  hashdump -y "$locsystem" -s "$locsam" >vol_hashdump_"${RUN_TIME}"
		./volatility_2.5_linux_x64 -f "$FNAME" --profile="$PCHOICE"  lsadump -y "$locsystem" -s "$locsecurity"  >vol_lsadump_"${RUN_TIME}" #service account passwords, autologon passwords
	}
	hiveinfo
	hivehash
	
	mkdir -p "$UOUTPUT/volatility2/vol_hivelist"
	mkdir -p "$UOUTPUT/volatility2/vol_hashdump"
	mkdir -p "$UOUTPUT/volatility2/vol_lsadump"
	mv vol_hivelist_"${RUN_TIME}"  "$UOUTPUT/volatility2/vol_hivelist/"
	mv vol_hashdump_"${RUN_TIME}"  "$UOUTPUT/volatility2/vol_hashdump/"	
	mv vol_lsadump_"${RUN_TIME}"  "$UOUTPUT/volatility2/vol_lsadump/"	
	echo "==============COMPLETED==============="
	}

function sidcheck() {
	echo "==========SID=========="
	./volatility_2.5_linux_x64 -f "$FNAME" --profile="$PCHOICE"  getsids >vol_getsids_"${RUN_TIME}"
	mkdir -p "$UOUTPUT/volatility2/vol_getsids"
	mv vol_getsids_"${RUN_TIME}" "$UOUTPUT/volatility2/vol_getsids/"
	echo "==============COMPLETED==============="
}
	
function volchoice2() {
	if [[ "$CFILE_VOL2" != "yes" ]]; then
		echo "Volatility2 is not compatible with file image. Aborting process"
		return 1
	fi
		
	mkdir -p "$UOUTPUT/volatility2" #the -p will help in creating any missing directory files in this volatility
		
	#Process information and store into file
	processinfo
	sleep 2
	#Network Connections into a file and display the network connections
	networkcon
	sleep 2
	#Commands executed and display commands 
	cmdcheck
	sleep 2	
	#dllist dump
	dllcheck
	sleep 2
	#Reg list and password dump
	hivechecks
	sleep 2			
	#SID List
	sidcheck
}
		
function volchoice3() {
	if [[ "$CFILE_VOL3" != "yes" ]]; then
		echo "Volatility is not compatible with file image. Aborting process"
		return 1
	fi
		
	mkdir -p "$UOUTPUT/volatility3" #the -p will help in creating any missing directory files in this volatility
	
	#Process information and store into file
	processinfo3
	sleep 2
	#Network Connections into a file and display the network connections
	networkcon3
	sleep 2
	#Commands executed and display commands 
	cmdcheck3
	sleep 2
	#dllist dump
	dllcheck3
	sleep 2
	#Reg list and password dump		
	hivechecks3
	sleep 2
	#SID Listsid
	sidcheck3
}	

function processinfo3(){
	echo "==========PROCESS INFORMATION=========="
	mkdir -p "$UOUTPUT/volatility3/vol_pslist"
	mkdir -p "$UOUTPUT/volatility3/vol_psscan"
	"$vol3_bin" -f "$FNAME" windows.pslist.PsList \
    > "$UOUTPUT/volatility3/vol_pslist/vol_pslist_${RUN_TIME}" \
    2>> "$UOUTPUT/volatility3/vol3_errors_${RUN_TIME}.log"
    "$vol3_bin" -f "$FNAME" windows.psscan.PsScan \
    > "$UOUTPUT/volatility3/vol_psscan/vol_psscan_${RUN_TIME}" \
    2>> "$UOUTPUT/volatility3/vol3_errors_${RUN_TIME}.log"
	echo "==============COMPLETED==============="
}

function cmdcheck3() {
	#Commands executed and display commands 
	echo "==========COMMANDS=========="
	mkdir -p "$UOUTPUT/volatility3/vol_cmdline"
	"$vol3_bin" -f "$FNAME" windows.cmdline.CmdLine \
	> "$UOUTPUT/volatility3/vol_cmdline/vol_cmdline_${RUN_TIME}" \
	2>> "$UOUTPUT/volatility3/vol3_errors_${RUN_TIME}.log"
	echo "==============COMPLETED==============="
}

function dllcheck3() {
	#dllist dump
	echo "==========Dllist=========="
	mkdir -p "$UOUTPUT/volatility3/vol_dlllist"
	"$vol3_bin" -f "$FNAME" windows.dlllist.DllList \
	> "$UOUTPUT/volatility3/vol_dlllist/vol_dlllist_${RUN_TIME}" \
	2>> "$UOUTPUT/volatility3/vol3_errors_${RUN_TIME}.log"
	echo "==============Completed==============="
}

function networkcon3() {
	#Network Connections and display connection
	echo "==========NETWORK CONNECTIONS========="
	mkdir -p "$UOUTPUT/volatility3/vol_netscan"
	"$vol3_bin" -f "$FNAME" windows.netscan.NetScan \
	> "$UOUTPUT/volatility3/vol_netscan/vol_netscan_${RUN_TIME}" \
	2>> "$UOUTPUT/volatility3/vol3_errors_${RUN_TIME}.log"
    echo "==============COMPLETED==============="
}

function hivechecks3() {
	#Extract Reg info
	echo "==========HIVELIST=========="
	mkdir -p "$UOUTPUT/volatility3/vol_hivelist"
	"$vol3_bin" -f "$FNAME" windows.registry.hivelist.HiveList \
	> "$UOUTPUT/volatility3/vol_hivelist/vol_hivelist_${RUN_TIME}" \
	2>> "$UOUTPUT/volatility3/vol3_errors_${RUN_TIME}.log"	
	echo "==============COMPLETED==============="
}

function sidcheck3() {
	echo "==========SID=========="
	mkdir -p "$UOUTPUT/volatility3/vol_getsids"
	"$vol3_bin" -f "$FNAME" windows.getsids.GetSIDs \
	> "$UOUTPUT/volatility3/vol_getsids/vol_getsids_${RUN_TIME}" \
	2>> "$UOUTPUT/volatility3/vol3_errors_${RUN_TIME}.log"
	echo "==============COMPLETED==============="
}	

function volcheck(){
	#Execution
	echo "Beginning Volatility versions check" 
	sleep 2
	if cfilevolver; then
		volchoice
	fi
	echo "Volatility versions check Ended"
}
