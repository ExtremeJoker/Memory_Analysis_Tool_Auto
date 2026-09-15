#!/bin/bash
#Give directory to story carving
#read -p "Please enter the file name: " FNAME #ONLY USE FOR TESTING FUNCTION LIBRARY
#read -p "Please enter a directory to store the output: " UOUTPUT
#mkdir "$UOUTPUT" 
function bulkextractor(){
	#read -p "Please enter the file name:" FNAME (Modify this code from the check mem_anal_check.sh file)
	#Bulk_extractor carving automation script
	function bulkcarve() {
		RUN_TIME=$(date '+%y-%m-%d_%H-%M-%S')
		bulk_extractor "$FNAME" -o "bulk_${FNAME}_${RUN_TIME}"
	}

	function bulkvalid() {
		if [ -d "bulk_${FNAME}_${RUN_TIME}" ]; then
			echo "$FNAME bulk extraction completed"
		else
			echo "Error: $FNAME was unable to be extracted"
			return 0
		fi
	}

	function bulksecure() {
		local src_dir="bulk_${FNAME}_${RUN_TIME}"
		BULK_MANIFEST="${UOUTPUT}/bulk_${FNAME}_${RUN_TIME}_manifest.sha256"
		generate_manifest "$src_dir" "$BULK_MANIFEST" 
		mv "$src_dir" "$UOUTPUT"
		verify_manifest "$BULK_MANIFEST" "$UOUTPUT"
	}
	
	function pcap_extractor() {
		local bulk_dir="bulk_${FNAME}_${RUN_TIME}"
		local pcap_path="$bulk_dir/packets.pcap"
		if [ -f "$pcap_path" ]; then
			local size
			size=$(du -h "$pcap_path" | cut -f1)
			echo "Network Traffic Found: packets.pcap found in $bulk_dir [Size: $size]"
			mv "$pcap_path" "$UOUTPUT"
		else
			echo "Network Traffic NOT Found: NO packets.pcap was found"
		fi
	}
	function searchbulk() {
		function runstring_search() {
			local target_dir="$UOUTPUT/bulk_${FNAME}_${RUN_TIME}"
			local raw_strings
			raw_strings=$(find "$target_dir" -type f -exec strings {} \;)	
			
			while true; do
				echo ""
				echo "Choose a string search method:"
				echo "  1) Categorized keyword search (one file, sectioned by keyword)"
				echo "  2) Per-keyword search (separate file per keyword)"
				echo "  3) Keyword list from a .conf file"
				echo "  4) Extract email addresses (regex)"
			    echo "  5) Automated credential/hash pattern scan"
				echo "  6) Done - continue with rest of script"
			    read -rp "Selection [1-6]: " CHOICE
			    
			    case "$CHOICE" in
					1) categorizedsearch "$raw_strings" ;;
					2) perkeywordsearch "$raw_strings" ;;
					3) confkeywordsearch "$raw_strings" ;;
					4) emailextract "$raw_strings" ;;
					5) passhash "$raw_strings" ;;
					6) echo "Exiting string search."; break ;;
					*) echo "Invalid selection, try again." ;;
				esac
			done
		}
		
		function categorizedsearch() {
			local raw_strings="$1"
			local output_file="Strings_categorized_${RUN_TIME}.txt"
			local KEYWORDS
			
			read -rp "Enter keywords separated by space: " -a KEYWORDS
			 > "$output_file"
			 
			for keyword in "${KEYWORDS[@]}"; do
				echo "===================${keyword}======================" >> "$output_file"
				echo "$raw_strings" | grep -i "$keyword" >> "$output_file"
			done
			
			mv "$output_file" "$UOUTPUT"
			echo "Categorized results save to $UOUTPUT/$output_file"
		}
		
		function perkeywordsearch() {
			local raw_strings="$1"
			local KEYWORDS
			
			read -rp "Enter keywords separated by space: " -a KEYWORDS
			
			for keyword in "${KEYWORDS[@]}"; do
				local output_file="Strings_${keyword}.txt"
				echo "$raw_strings" | grep -i "$keyword" > "$output_file"
				mv "$output_file" "$UOUTPUT"
				echo "Categorized results save to $UOUTPUT/$output_file"
			done
		}
		
		function confkeywordsearch() {
			local raw_strings="$1"
			local CONF_FILE
			
			read -rp "Enter path to keyword .conf file:" CONF_FILE
			
			if [[ ! -f "$CONF_FILE" ]]; then
				echo "Error: $CONF_FILE NOT found"
				return 1
			fi
			
			while read -r keyword; do
				[[ -z "$keyword" ]] && continue
				local output_file="Strings_${keyword}.txt"
				echo "$raw_strings" | grep -i "$keyword" > "$output_file"
				mv "$output_file" "$UOUTPUT"
				echo "Categorized results save to $UOUTPUT/$output_file"
			done < "$CONF_FILE"
		}
		
		function emailextract() {
			local raw_strings="$1"
			local output_file="Strings_EMAIL.txt"
			
			echo "$raw_strings" | grep -Eo "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" > "$output_file"
			mv "$output_file" "$UOUTPUT"
			echo "Email addresses saved to $UOUTPUT/$output_file"
		}
		function passhash() {
			local raw_strings="$1"
			local report_file="password_hash_report_${RUN_TIME}.txt"
			
			>"$report_file"
			
			echo "==========HIGH-CONFIDENCE MATCHES (STRUCTURAL FORMAT)=============" >> "$report_file"
			echo "==========UNIX /etc/shadow style (\$id\$salt\$hash)=============" >> "$report_file" #Linux OS system scan
			echo "$raw_strings" | grep -E '\$(1|2a|2b|2y|5|6|y)\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{20,}' >> "$report_file"
			
			echo "==========WINDOWS SAM/pwdump style (user:uid:LM:NTLM:::)==========">>"$report_file" #Wins OS system scan
			echo "$raw_strings" | grep -E '^[^:]+:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::' >> "$report_file"
			
			echo "==========bcrypt (\$2a\$/\$2b\$/\$2y\$ full form)==========" >> "$report_file" # Type of Password Hashing
			echo "$raw_strings" | grep -E '\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{53}' >> "$report_file"
			
			local high_conf_count
			high_conf_count=$(grep -Ec '\$(1|2a|2b|2y|5|6|y)\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{20,}|^[^:]+:[0-9]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::' <<< "$raw_strings")
			
			echo "" >> "$report_file"
			
			echo "==========LOWER-CONFIDENCE MATCHES (BARE HEX LENGTH BASED ONLY)==========" >> "$report_file" #Lower confidnece
			echo "==========Possible MD5 (32 hex chars)==========" >> "$report_file"
			echo "$raw_strings" | grep -Eow '[A-Fa-f0-9]{32}' >> "$report_file"
			echo "==========Possible SHA1 (40 hex chars)==========" >> "$report_file"
			echo "$raw_strings" | grep -Eow '[A-Fa-f0-9]{40}' >> "$report_file"
			echo "==========Possible SHA256 (64 hex chars)==========" >> "$report_file"
			echo "$raw_strings" | grep -Eow '[A-Fa-f0-9]{64}' >> "$report_file"
			
			local md5_count sha1_count sha256_count
			md5_count=$(grep -Eow '[A-Fa-f0-9]{32}' <<< "$raw_strings" | wc -l)
			sha1_count=$(grep -Eow '[A-Fa-f0-9]{40}' <<< "$raw_strings" | wc -l)
			sha256_count=$(grep -Eow '[A-Fa-f0-9]{64}' <<< "$raw_strings" | wc -l)
			
			mv "$report_file" "$UOUTPUT"
			HASH_SUMMARY="High-confidence: ${high_conf_count} | Possible MD5: ${md5_count} | Possible SHA1: ${sha1_count} | Possible SHA256: ${sha256_count}"
			echo "Scan complete. $HASH_SUMMARY"
			echo "Full report saved to $UOUTPUT/$(basename "$report_file")"
		}
			
	 #Execution
	 runstring_search
	}
	#Execution
	echo "=====================================BULK CARVING====================================="
	bulkcarve
	sleep 2
	echo "=====================================VALIDATING BULK====================================="
	if ! bulkvalid; then
		return 1
	fi
	sleep 2
	echo "======================================EXTRACTING PCAP====================================="
	pcap_extractor
	sleep 2
	echo "======================================HASH VALIDATION====================================="
	bulksecure
	sleep 2
	echo "======================================STRING SEARCH====================================="
	searchbulk
}

function foremost_() {
	function forecarve(){
		foremost -i "$FNAME" -o foremost_"${FNAME}" -t all -T #forecast disk for images
		shopt -s nullglob
		matches=(foremost_"${FNAME}"_*)
		shopt -u nullglob
	}
	
	function forevalid() {
		 if (( ${#matches[@]} > 0 )) && [ -d "${matches[0]}" ]; then
			echo "$FNAME foremost extraction completed"
		else
			echo "Error: $FNAME was unable to be extracted"
			return 1
		fi
	}
	function foresecure() {
		local src_dir="${matches[0]}"
		FOREMOST_MANIFEST="${UOUTPUT}/${src_dir}_manifest.sha256"
		
		
		generate_manifest "$src_dir" "$FOREMOST_MANIFEST"
		mv "$src_dir" "$UOUTPUT"   #The reason the code was made this way is the folder has been created to store info earlier
		verify_manifest "$FOREMOST_MANIFEST" "$UOUTPUT"
	}
	
	#Execution
	echo "=====================================FOREMOST CARVING====================================="
	if ! forecarve; then
        echo "Error: Foremost failed to execute successfully"
        return 1
    fi
    sleep 2
    echo "=====================================FOREMOST VALIDATION====================================="
    if ! forevalid; then
        return 1
    fi
    sleep 2
    echo "=====================================HASH VALIDATION====================================="
    foresecure
}

#Prep for HASH validation checks
function generate_manifest(){
	# $1-place holder for the directory wanna hash
	# $2-place holder for the path to place the output
    local target_dir="$1"
    local manifest_file="$2"
	
	while true; do
        if [[ -d "$target_dir" ]]; then
            break
        fi
	
		echo "Error: $target_dir is not a valid directory"
        read -p "Re-enter target directory? [Y/N]: " CHOICE
        CHOICE="${CHOICE,,}"  #Lowercase the answer to ensure logic works
		
		if [[ "$CHOICE" == "y" ]]; then
            read -p "Enter target directory: " target_dir
        else
            echo "Unable to hash. Proceeding with other task."
            return 1
        fi
	done
	
	if find "$target_dir" -type f -exec sha256sum {} \; > "$manifest_file" 2>/dev/null; then
		echo "Manifest written to $manifest_file"
		echo "(copy this path for verify_manifest: $manifest_file)"
	else
		echo "Error: could not write manifest to $manifest_file (check the path exists)"
		return 1
	fi
}	

#Validate the Hash against baseline for chain of custody
function verify_manifest() {
	#$1 = Original Maniest File (Path BEFORE the move)
	#$2 = New base Directory (Path AFTER the move) 
	local old_manifest="$1"
	local new_base="$2"
	local mismatch=0
	
	while true; do
		if [[ -f "$old_manifest" ]]; then
			break
		fi

		echo "Error: $old_manifest is not a valid file"
		read -p "Re-enter manifest file path? [Y/N]: " CHOICE
		CHOICE="${CHOICE,,}"

		if [[ "$CHOICE" == "y" ]]; then
			read -p "Enter manifest file path: " old_manifest
		else
			echo "Unable to verify. Proceeding with other task."
			return 1
		fi
	done
	
	while true; do
		if [[ -d "$new_base" ]]; then
			break
		fi

		echo "Error: $new_base is not a valid directory"
		read -p "Re-enter new base directory? [Y/N]: " CHOICE
		CHOICE="${CHOICE,,}"

		if [[ "$CHOICE" == "y" ]]; then
			read -p "Enter new base directory: " new_base
		else
			echo "Unable to verify. Proceeding with other task."
			return 1
		fi
	done
	
	while read -r hash old_path; do
		local fname
		fname=$(basename "$old_path")
		local new_path
		new_path=$(find "$new_base" -type f -name "$fname" -print -quit)

		if [[ -z "$new_path" ]]; then
			echo "MISSING: $fname not found under $new_base"
			mismatch=1
			continue
		fi
		
		local new_hash
		new_hash=$(sha256sum "$new_path" | awk '{print $1}')

		if [[ "$hash" == "$new_hash" ]]; then
			echo "OK: $fname integrity verified ($hash)"
		else
			echo "MISMATCH: $fname hash changed! Original: $hash Now: $new_hash"
			mismatch=1
		fi
	done < "$old_manifest"

	if [[ $mismatch -eq 0 ]]; then
		echo "All files verified - chain of custody intact"
		return 0
	else
		echo "WARNING: One or more files failed integrity verification"
		return 1
	fi
}

#Execution together - ONLY USE FOR INTERNAL FUNCTION LIBRARY TESTING
#bulkextractor
#sleep 1
#foremost_
