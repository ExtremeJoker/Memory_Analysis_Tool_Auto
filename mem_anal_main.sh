#!/bin/bash
#Function Library Imports
source ./mem_anal_checks.sh
source ./mem_anal_carving.sh
source ./mem_anal_sum.sh

#Timer to record the script's run 
SECONDS=0
#Validate root and file being investigated
echo "=====================================TASK BEGINS====================================="
sleep 2
echo "=====================================ROOT CHECKs====================================="
checkroot
sleep 2  
echo "=====================================FILE CHECKS====================================="
checkfile
sleep 2

read -p "Please enter a directory to store the output: " UOUTPUT   # Create the file to store the output
mkdir "$UOUTPUT" 

#Validate and ensure tools are installed OR process of installing
echo "===================================TOOLS INSTALL(ED)====================================="
checktools
sleep 2
installtools

#Carving investigation of file for investigation
bulkextractor
sleep 2
foremost_
sleep 2
genstats
echo "=====================================TASK COMPLETED======================================"
