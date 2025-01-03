#!/usr/bin/env bash

excho "Flush iftop statistic into a file - top 30 linws - one second based"
# https://www.geeksforgeeks.org/iftop-command-in-linux-with-examples/

count=1
while [ $count -le 2 ]; do
  echo "run.."
  iftop -t -s 11 -L 30 -n -P  2>&1 > iftop-out.txt
  cat iftop-out.txt > iftop-result.txt
  sleep 1
done
