#!/bin/bash
#Check for sudo Privilege - Script requires sudo level
SUDO_CHECK=$(sudo whoami 2>/dev/null)

function checkroot() {
	if [[ "$SUDO_CHECK" == "root" ]]; then
		echo "sudo privilege detected"
		sleep 2
	else
		echo "sudo privilege not detected"
		sleep 1
		echo "This script requires sudo privilege. Script will now end have a nice day."
		exit 1 #General failure hence why exit 1
	fi
}

#Verify if the file is actually on the systems
function checkfile() {
	local U_REP
	
	while true; do
		read -rp "Please input the file OR the filename: " FNAME #Line that sets which file is investigated
		# if user give just the filepath full or partial. Execute this code
		if [[ -f $FNAME ]]; then
			echo "File for analysing found. Proceeding..."
			return 0
		fi
		# if user give just the filename. Execute this code
		local MATCH
		MATCH=$(find . -type f -name "$FNAME" -print -quit)
	
		if [[ -n "$MATCH" ]]; then
			FNAME="$MATCH"
			echo "File for analysing found $MATCH. Proceeding..."
			return 0
		fi
		# if file not found
		read -rp "Error:Unable to locate file for analysing. Try again? [Y/N] " U_REP
		CHECK_U_REP="${U_REP,,}"
		if [[ "$CHECK_U_REP" == "y" ]]; then
			continue
		else
			echo "Have a nice day"
			return 1
		fi
	done
}

#Verify and validate all the tools inst
function checktools() {
	TOOLS=(bulk_extractor foremost dd scalpel vol)
	MISSING_TOOLS=()
	echo "Begin validation check for files installed"
	for tool in "${TOOLS[@]}"; do
		if ! command -v "$tool" &>/dev/null; then
			echo "NOTE: You do not have the necessary $tool installed"
			MISSING_TOOLS+=("$tool")
		fi
	done 
	if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
		echo "The following tools are NOT installed ${MISSING_TOOLS[*]}"
	fi
	sleep 2
	echo "Checks completed"
}

#Collate the missing tools and install it
function installtools() {
	if [[ ${#MISSING_TOOLS[@]} -eq 0 ]]; then
        echo "Nothing to install"
        return 0
    fi
    for tool in "${MISSING_TOOLS[@]}"; do
		case "$tool" in
			vol)
			echo "Note: Installing volatility3 (provides 'vol') using pip.."
			pip install volatility3 --break-system-packages
			;;
			*)
			echo "Note: Installing $tool using apt"
            sudo apt install -y "$tool"
            ;;
        esac
    done
}

#Executable list - ONLY USE FOR INTERNAL FUNCTION LIBRARY TESTING
#checkroot
#sleep 2  
#checkfile
#sleep 2
#checktools
#sleep 2
#installtools
