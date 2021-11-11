#!/usr/bin/env bash

# VOY POR LA PAGINA 51
#Scored
#Failure to comply with "Scored" recommendations will decrease the final benchmark score.
#Compliance with "Scored" recommendations will increase the final benchmark score.
#Not Scored

#Failure to comply with "Not Scored" recommendations will not decrease the final
#benchmark score. Compliance with "Not Scored" recommendations will not increase the
#final benchmark score.
#

banner() {
  echo "     ██████╗██╗███████╗               █████╗ ██╗     ██████╗ ";
  echo "    ██╔════╝██║██╔════╝              ██╔══██╗██║     ╚════██╗";
  echo "    ██║     ██║███████╗    █████╗    ███████║██║      █████╔╝";
  echo "    ██║     ██║╚════██║    ╚════╝    ██╔══██║██║     ██╔═══╝ ";
  echo "    ╚██████╗██║███████║              ██║  ██║███████╗███████╗";
  echo "     ╚═════╝╚═╝╚══════╝              ╚═╝  ╚═╝╚══════╝╚══════╝";
  echo "                                                             ";
  echo " CIS - Amazon Linux 2 - BenchMark v1.0"
  echo -e " https://www.cisecurity.org/benchmark/amazon_linux/ \n\n\n"
}

passed="\e[1m\e[92m"
fail="\e[1m\e[91m"
end="\e[0m"
good="[\e[92m+${end}]"
bad="[\e[91m-${end}]"
slp="sleep 0.2"

getTime() {
  local datestamp
  datestamp=$(date)
  return "$datestamp"
}

initCSV() {
  local content="ID,NAME,SCORE"
  report="/tmp/CIS-report.csv"
  touch $report
  echo $content > $report
}

checkL1() {
  local checks=0
  local counter=0

  modprobe -n -v cramfs > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 1.1.1.1 Ensure mounting of cramfs filesystems is disabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 1.1.1.1 Ensure mounting of cramfs filesystems is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "1.1.1.1, Ensure mounting of cramfs filesystems is disabled, $out" >> $report
  checks=$((checks+1))
  $slp

  modprobe -n -v hfs > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 1.1.1.2 Ensure mounting of hfs filesystems is disabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 1.1.1.2 Ensure mounting of hfs filesystems is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "1.1.1.2, Ensure mounting of hfs filesystems is disabled, $out" >> $report
  checks=$((checks+1))
  $slp

  modprobe -n -v hfsplus > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 1.1.1.3 Ensure mounting of hfsplus filesystems is disabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 1.1.1.3 Ensure mounting of hfsplus filesystems is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "1.1.1.3, Ensure mounting of hfsplus filesystems is disabled, $out" >> $report
  checks=$((checks+1))
  $slp

  modprobe -n -v squashfs > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 1.1.1.4 Ensure mounting of squashfs filesystems is disabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 1.1.1.4 Ensure mounting of squashfs filesystems is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "1.1.1.4, Ensure mounting of squashfs filesystems is disabled, $out" >> $report
  checks=$((checks+1))
  $slp

  modprobe -n -v udf > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 1.1.1.5 Ensure mounting of udf filesystems is disabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 1.1.1.5 Ensure mounting of udf filesystems is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "1.1.1.5, Ensure mounting of udf filesystems is disabled, $out" >> $report
  checks=$((checks+1))
  $slp

  mount | grep /tmp > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.2 Ensure /tmp is configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.2 Ensure /tmp is configured [${fail}${out}${end}]"
  fi
  echo "1.1.2, Ensure /tmp is configured, $out" >> $report
  checks=$((checks+1))
  $slp

  mount | grep /tmp | grep nodev > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.3 Ensure nodev option set on /tmp partition [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.3 Ensure nodev option set on /tmp partition [${fail}${out}${end}]"
  fi
  echo "1.1.3, Ensure nodev option set on /tmp partition, $out" >> $report
  checks=$((checks+1))
  $slp

  mount | grep /tmp | grep nosuid > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.4 Ensure nosuid option set on /tmp partition [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.4 Ensure nosuid option set on /tmp partition [${fail}${out}${end}]"
  fi
  echo "1.1.4, Ensure nosuid option set on /tmp partition, $out" >> $report
  checks=$((checks+1))
  $slp

  mount | grep /tmp | grep noexec > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.5 Ensure noexec option set on /tmp partition [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.5 Ensure noexec option set on /tmp partition [${fail}${out}${end}]"
  fi
  echo "1.1.5, Ensure noexec option set on /tmp partition, $out" >> $report
  checks=$((checks+1))
  $slp

  cat /etc/fstab | grep '/var' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.6 Ensure separate partition exists for /var [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.6 Ensure separate partition exists for /var [${fail}${out}${end}]"
  fi
  echo "1.1.6, Ensure separate partition exists for /var, $out" >> $report
  checks=$((checks+1))
  $slp

  cat /etc/fstab | grep '/var/tmp' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.7 Ensure separate partition exists for /var/tmp [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.7 Ensure separate partition exists for /var/tmp [${fail}${out}${end}]"
  fi
  echo "1.1.7, Ensure separate partition exists for /var/tmp, $out" >> $report
  checks=$((checks+1))
  $slp

  mount | grep '/var/tmp' | grep 'nodev' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.8 Ensure nodev option set on /var/tmp partition [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.8 Ensure nodev option set on /var/tmp partition [${fail}${out}${end}]"
  fi
  echo "1.1.8, Ensure nodev option set on /var/tmp partition, $out" >> $report
  checks=$((checks+1))
  $slp

  mount | grep '/var/tmp' | grep 'nosuid' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.9 Ensure nosuid option set on /var/tmp partition [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.9 Ensure nosuid option set on /var/tmp partition [${fail}${out}${end}]"
  fi
  echo "1.1.9, Ensure nosuid option set on /var/tmp partition, $out" >> $report
  checks=$((checks+1))
  $slp

  mount | grep '/var/tmp' | grep 'noexec' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.10 Ensure noexec option set on /var/tmp partition [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.10 Ensure noexec option set on /var/tmp partition [${fail}${out}${end}]"
  fi
  echo "1.1.10, Ensure noexec option set on /var/tmp partition, $out" >> $report
  checks=$((checks+1))
  $slp

  cat /etc/fstab | grep '/var/log' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.11 Ensure separate partition exists for /var/log [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.11 Ensure separate partition exists for /var/log [${fail}${out}${end}]"
  fi
  echo "1.1.11, Ensure separate partition exists for /var/log, $out" >> $report
  checks=$((checks+1))
  $slp

  cat /etc/fstab | grep '/var/log/audit' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.12 Ensure separate partition exists for /var/log/audit [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.12 Ensure separate partition exists for /var/log/audit [${fail}${out}${end}]"
  fi
  echo "1.1.12, Ensure separate partition exists for /var/log/audit, $out" >> $report
  checks=$((checks+1))
  $slp

  mount | grep '/home' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.13 Ensure separate partition exists for /home [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.13 Ensure separate partition exists for /home [${fail}${out}${end}]"
  fi
  echo "1.1.13, Ensure separate partition exists for /home, $out" >> $report
  checks=$((checks+1))
  $slp

  mount | grep '/home' | grep 'nodev' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.14 Ensure nodev option set on /home partition [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.14 Ensure nodev option set on /home partition [${fail}${out}${end}]"
  fi
  echo "1.1.14, Ensure nodev option set on /home partition, $out" >> $report
  checks=$((checks+1))
  $slp

  mount | grep /dev/shm | grep 'nodev' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.15 Ensure nodev option set on /dev/shm partition [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.15 Ensure nodev option set on /dev/shm partition [${fail}${out}${end}]"
  fi
  echo "1.1.15, Ensure nodev option set on /dev/shm partition, $out" >> $report
  checks=$((checks+1))
  $slp

  mount | grep /dev/shm | grep 'nosuid' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.16 Ensure nosuid option set on /dev/shm partition [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.16 Ensure nosuid option set on /dev/shm partition [${fail}${out}${end}]"
  fi
  echo "1.1.16, Ensure nosuid option set on /dev/shm partition, $out" >> $report
  checks=$((checks+1))
  $slp

  mount | grep /dev/shm | grep 'noexec' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.17 Ensure noexec option set on /dev/shm partition [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.17 Ensure noexec option set on /dev/shm partition [${fail}${out}${end}]"
  fi
  echo "1.1.17, Ensure noexec option set on /dev/shm partition, $out" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${good} 1.1.18 Ensure sticky bit is set on all world-writable directories [${passed}! MANUAL !${end}]"
  counter=$((counter+1))
  echo "1.1.18, Ensure sticky bit is set on all world-writable directories, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  systemctl is-enabled autofs 2>/dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.1.19 Disable Automounting [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.1.19 Disable Automounting [${fail}${out}${end}]"
  fi
  echo "1.1.19, Disable Automounting, $out" >> $report
  checks=$((checks+1))
  $slp







  echo $checks
  echo $counter


}

banner
initCSV
checkL1


