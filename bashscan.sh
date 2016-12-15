#!/bin/bash
dir="$PWD/bashscan"
list=$dir/fileList.txt
log=$dir/virusLog.txt
strs=$dir/fileStrings
report=$dir/report.txt
badFiles=$dir/badfiles.txt
mkdir -p bashscan/fileStrings
echo '' > $list
echo '' > $log
echo -e "\n\nBashscan Report\n----------------\n" > $report
echo '' > $badFiles
if [ $2 ];then
	echo "Creating file list"
	
	# Create a list of files with absolute paths
	find $2 -type f -exec readlink -f {} \; > $list

	# Exclude bashscans files and signature files from the scan
	cat $list | grep -v $dir | grep -v "$(find $1 -type f -exec readlink -f {} \;)" > $list
	
	totalFiles="$(cat $list | wc -l)"
	echo "Searching through $totalFiles files"
	
	# Initialize variables for stats
	counter=0
	hits=0
	matches=0
	
	# Analize strings output of all the files
	while read line
	do
		name="$(echo "$line" | sed "s/.*\///").Strings$counter"
		strings "$line" > "$strs/$name"

		# Compare strings output with signature file
		result="$(grep --color=always -HnFf $1 "$strs/$name")"
		if [ "$result" ];then
			result="$(echo "$result" | sed "s|$strs\/$name|$line|g")"
			echo "$result"

			# Compute stats and add to logs
			hits=$[$hits+1]
			currentMatches="$(echo "$result" | wc -l)"
			matches=$(($matches+$currentMatches))
			echo $matches
			echo "$result" >> $log
			echo "$line" >> $badFiles
		fi
		# remove .Strings files as you go. Comment out for debugging
		rm -f "$strs/$name"
		counter=$[$counter+1]
		echo "Searching... $counter/$totalFiles"
	done < $list

	# Some Cleanup
	rm -rf $strs

	# Generate Report
	sort -u $badFiles
	echo -n "Matched Files:" >> $report
	cat $badFiles >> $report
	echo -e "\nTotal number of unique files with hits: $hits" >> $report
	echo "Total number of signatures matched: $matches" >> $report
	echo "Total files analyized: $counter" >> $report
	echo -e "\nFor more information view ./bashscan/virusLog.txt and ./bashscan/report.txt" >> $report
	cat $report
else
	# error checking
	echo -e "Give me 2 arguments\n./bashscan.sh signatures path"
fi
