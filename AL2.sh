#!/usr/bin/env bash

#Scored
#Failure to comply with "Scored" recommendations will decrease the final benchmark score.
#Compliance with "Scored" recommendations will increase the final benchmark score.
#Not Scored

#Failure to comply with "Not Scored" recommendations will not decrease the final
#benchmark score. Compliance with "Not Scored" recommendations will not increase the
#final benchmark score.
#

banner() {
  # banner here
  local n=0
}

getTime() {
  local datestamp
  datestamp=$(date)
  return "$datestamp"
}

initCSV() {
  local content="ID,NAME,SCORE"
  local report="CIS-report.csv"
  if [[ -w . ]]; then
    touch CIS-report.csv
    return $report
  else
    touch /tmp/CIS-report.csv
    local report="/tmp/CIS-report.csv"
    return $report
  fi
}

reportName=initCSV

checkL1() {
  modprobe -n -v cramfs >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
  else
    local out="PASS"
  fi
  echo "1.1.1.1, Ensure mounting of cramfs filesystems is disabled, $out" >> $reportName
  echo -e "1.1.1.1 Ensure mounting of cramfs filesystems is disabled [${out}]"


}
