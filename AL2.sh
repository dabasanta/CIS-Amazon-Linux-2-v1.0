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

  sudo systemctl is-enabled autofs > /dev/null 2>&1
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

  echo -e "${good} 1.2.1 Ensure package manager repositories are configured [${passed}! MANUAL !${end}]"
  counter=$((counter+1))
  echo "1.2.1, Ensure package manager repositories are configure, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${good} 1.2.2 Ensure GPG keys are configured [${passed}! MANUAL !${end}]"
  counter=$((counter+1))
  echo "1.2.2, Ensure GPG keys are configured, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${good} 1.2.3 Ensure gpgcheck is globally activated [${passed}! MANUAL !${end}]"
  counter=$((counter+1))
  echo "1.2.3, Ensure gpgcheck is globally activated, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${good} 1.3.1 Ensure AIDE is installed [${passed}! MANUAL !${end}]"
  counter=$((counter+1))
  echo "1.3.1, Ensure AIDE is installed, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  grep -r aide /etc/cron.* /etc/crontab > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.3.2 Ensure filesystem integrity is regularly checked [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.3.2 Ensure filesystem integrity is regularly checked [${fail}${out}${end}]"
  fi
  echo "1.3.2, Ensure filesystem integrity is regularly checked, $out" >> $report
  checks=$((checks+1))
  $slp

  echo -e "\n${good}1.4. Secure Boot Settings${end}\n"

  if test -f "/boot/grub2/grub.cfg"; then
    uid=$(stat /boot/grub2/grub.cfg | grep 'Uid' | awk '{print $5}' | tr -d '/')
    gid=$(stat /boot/grub2/grub.cfg | grep 'Uid' | awk '{print $9}' | tr -d '/')
    if [ $uid -eq 0 ] && [ $gid -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 1.4.1 Ensure permissions on bootloader config are configured [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 1.4.1 Ensure permissions on bootloader config are configured [${fail}${out}${end}]"
    fi
    echo "1.4.1, Ensure permissions on bootloader config are configured, $out" >> $report
    checks=$((checks+1))
    $slp
  fi
  if test -f "/boot/grub/grub.cfg"; then
    uid=$(stat /boot/grub/grub.cfg | grep 'Uid' | awk '{print $5}' | tr -d '/')
    gid=$(stat /boot/grub/grub.cfg | grep 'Uid' | awk '{print $9}' | tr -d '/')
    if [ $? -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 1.4.1 Ensure permissions on bootloader config are configured [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 1.4.1 Ensure permissions on bootloader config are configured [${fail}${out}${end}]"
    fi
    echo "1.4.1, Ensure permissions on bootloader config are configured, $out" >> $report
    checks=$((checks+1))
    $slp
  fi

  echo -e "${good} 1.4.2 Ensure authentication required for single user mode [${passed}! MANUAL !${end}]"
  counter=$((counter+1))
  echo "1.4.2, Ensure authentication required for single user mode, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  echo -e "\n${good}1.5. Additional Process Hardening${end}\n"

  local dumpeable
  dumpeable=$(sysctl fs.suid_dumpable | cut -d '=' -f 2 | sed 's/\s//g')
  if [ "$dumpeable" -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.5.1 Ensure core dumps are restricted [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.5.1 Ensure core dumps are restricted [${fail}${out}${end}]"
  fi
  echo "1.5.1, Ensure core dumps are restricted, $out" >> $report
  checks=$((checks+1))
  $slp

  local aslr
  aslr=$(sysctl kernel.randomize_va_space | cut -d '=' -f 2 | sed 's/\s//g')
  if [ "$aslr" == "2" ]; then
    local out="PASS"
    echo -e "${good} 1.5.2 Ensure address space layout randomization (ASLR) is enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.5.2 Ensure address space layout randomization (ASLR) is enabled [${fail}${out}${end}]"
  fi
  echo "1.5.2, Ensure address space layout randomization (ASLR) is enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  rpm -q prelink > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 1.5.3 Ensure prelink is disabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 1.5.3 Ensure prelink is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "1.5.3, Ensure prelink is disabled, $out" >> $report
  checks=$((checks+1))
  $slp

  echo -e "\n${good}1.6 Mandatory Access Control${end}\n"

  #1.6.1.1 Ensure SELinux is not disabled in bootloader configuration
  #grep "^\s*linux" /boot/grub2/grub.cfg

  grep SELINUX=enforcing /etc/selinux/config > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.6.1.2 Ensure the SELinux state is enforcing [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.6.1.2 Ensure the SELinux state is enforcing [${fail}${out}${end}]"
  fi
  echo "1.6.1.2, Ensure the SELinux state is enforcing, $out" >> $report
  checks=$((checks+1))
  $slp

  local status
  status=$(sestatus | cut -d : -f 2 | sed 's/\s//g')
  if [ "$status" == "targeted" ]; then
    local out="PASS"
    echo -e "${good} 1.6.1.3 Ensure SELinux policy is configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.6.1.3 Ensure SELinux policy is configured [${fail}${out}${end}]"
  fi
  echo "1.6.1.3, Ensure SELinux policy is configured, $out" >> $report
  checks=$((checks+1))
  $slp

  rpm -q setroubleshoot > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 1.6.1.4 Ensure SETroubleshoot is not installed [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 1.6.1.4 Ensure SETroubleshoot is not installed [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "1.6.1.4, Ensure SETroubleshoot is not installed, $out" >> $report
  checks=$((checks+1))
  $slp

  rpm -q mcstrans > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 1.6.1.5 Ensure the MCS Translation Service (mcstrans) is not installed [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 1.6.1.5 Ensure the MCS Translation Service (mcstrans) is not installed [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "1.6.1.5, Ensure the MCS Translation Service (mcstrans) is not installed, $out" >> $report
  checks=$((checks+1))
  $slp

  #1.6.1.6 Ensure no unconfined daemons exist
  #ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'

  rpm -q libselinux > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 1.6.2 Ensure SELinux is installed [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 1.6.2 Ensure SELinux is installed [${fail}${out}${end}]"
  fi
  echo "1.6.2, Ensure SELinux is installed, $out" >> $report
  checks=$((checks+1))
  $slp

  echo -e "\n${good}1.7 Warning Banners${end}\n"

  grep -E '(\\v|\\r|\\m|\\s|\\S|Amazon)' /etc/motd > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 1.7.1.1 Ensure message of the day is configured properly [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 1.7.1.1 Ensure message of the day is configured properly [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "1.7.1.1, Ensure message of the day is configured properly, $out" >> $report
  checks=$((checks+1))
  $slp

  grep -E '(\\v|\\r|\\m|\\s|\\S|Amazon)' /etc/issue > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 1.7.1.2 Ensure local login warning banner is configured properly [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 1.7.1.2 Ensure local login warning banner is configured properly [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "1.7.1.2, Ensure local login warning banner is configured properly, $out" >> $report
  checks=$((checks+1))
  $slp

  grep -E '(\\v|\\r|\\m|\\s|\\S|Amazon)' /etc/issue.net > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 1.7.1.3 Ensure remote login warning banner is configured properly [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 1.7.1.3 Ensure remote login warning banner is configured properly [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "1.7.1.3, Ensure remote login warning banner is configured properly, $out" >> $report
  checks=$((checks+1))
  $slp

  if test -f "/etc/motd"; then
    uid=$(stat /etc/motd | grep 'Uid' | awk '{print $5}' | tr -d '/')
    gid=$(stat /etc/motd | grep 'Uid' | awk '{print $9}' | tr -d '/')
    if [ $uid -eq 0 ] && [ $gid -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 1.7.1.4 Ensure permissions on /etc/motd are configured [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 1.7.1.4 Ensure permissions on /etc/motd are configured [${fail}${out}${end}]"
    fi
    echo "1.7.1.4, Ensure permissions on /etc/motd are configured, $out" >> $report
    checks=$((checks+1))
    $slp
  fi

  if test -f "/etc/issue"; then
    uid=$(stat /etc/issue | grep 'Uid' | awk '{print $5}' | tr -d '/')
    gid=$(stat /etc/issue | grep 'Uid' | awk '{print $9}' | tr -d '/')
    if [ $uid -eq 0 ] && [ $gid -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 1.7.1.5 Ensure permissions on /etc/issue are configured [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 1.7.1.5 Ensure permissions on /etc/issue are configured [${fail}${out}${end}]"
    fi
    echo "1.7.1.5, Ensure permissions on /etc/issue are configured, $out" >> $report
    checks=$((checks+1))
    $slp
  fi

  if test -f "/etc/issue.net"; then
    uid=$(stat /etc/issue.net | grep 'Uid' | awk '{print $5}' | tr -d '/')
    gid=$(stat /etc/issue.net | grep 'Uid' | awk '{print $9}' | tr -d '/')
    if [ $uid -eq 0 ] && [ $gid -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 1.7.1.6 Ensure permissions on /etc/issue.net are configured [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 1.7.1.6 Ensure permissions on /etc/issue.net are configured [${fail}${out}${end}]"
    fi
    echo "1.7.1.6, Ensure permissions on /etc/issue.net are configured, $out" >> $report
    checks=$((checks+1))
    $slp
  fi

  echo -e "\n${good}Check Security updates${end}\n"
  yum check-update --security > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 1.8 Ensure updates, patches, and additional security software are installed [${fail}! MANUAL !${end}]"
  else
    local out="PASS"
    echo -e "${good} 1.8 Ensure updates, patches, and additional security software are installed [${passed}! MANUAL !${end}]"
    counter=$((counter+1))
  fi
  echo "1.8, Ensure updates patches and additional security software are installed, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  echo -e "\n${good}2. Services${end}\n2.1 Special Purpose Services\n"

  rpm -q ntp > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    rpm -q chrony > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 2.1.1.1 Ensure time synchronization is in use [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 2.1.1.1 Ensure time synchronization is in use [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 2.1.1.1 Ensure time synchronization is in use [${fail}${out}${end}]"
  fi
  echo "2.1.1.1, Ensure time synchronization is in use, $out" >> $report
  checks=$((checks+1))
  $slp

  if [ -f "/etc/ntp.conf" ] && [ -f "/etc/sysconfig/ntpd" ];then
    grep "^restrict" /etc/ntp.conf > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      grep "^(server|pool)" /etc/ntp.conf > /dev/null 2>&1
      if [ $? -eq 0 ]; then
        grep "^OPTIONS" /etc/sysconfig/ntpd > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            grep "^ExecStart" /usr/lib/systemd/system/ntpd.service > /dev/null 2>&1
            if [ $? -eq 0 ]; then
              local out="PASS"
              echo -e "${good} 2.1.1.2 Ensure ntp is configured [${passed}${out}${end}]"
              counter=$((counter+1))
            else
              local out="FAIL"
              echo -e "${bad} 2.1.1.2 Ensure ntp is configured [${fail}${out}${end}]"
            fi
        else
          local out="FAIL"
          echo -e "${bad} 2.1.1.2 Ensure ntp is configured [${fail}${out}${end}]"
        fi
      else
        local out="FAIL"
        echo -e "${bad} 2.1.1.2 Ensure ntp is configured [${fail}${out}${end}]"
      fi
    else
      local out="FAIL"
      echo -e "${bad} 2.1.1.2 Ensure ntp is configured [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 2.1.1.2 Ensure ntp is configured [${fail}${out}${end}]"
  fi
  echo "2.1.1.2, Ensure ntp is configured, $out" >> $report
  checks=$((checks+1))
  $slp

  if [ -f "/etc/chrony.conf" ] && [ -f "/etc/sysconfig/chronyd" ];then
    grep "^(server|pool)" /etc/chrony.conf > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      grep ^OPTIONS /etc/sysconfig/chronyd > /dev/null 2>&1
      if [ $? -eq 0 ]; then
        local out="PASS"
        echo -e "${good} 2.1.1.3 Ensure chrony is configured [${passed}${out}${end}]"
        counter=$((counter+1))
      else
        local out="FAIL"
        echo -e "${bad} 2.1.1.3 Ensure chrony is configured [${fail}${out}${end}]"
      fi
    else
      local out="FAIL"
      echo -e "${bad} 2.1.1.3 Ensure chrony is configured [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 2.1.1.3 Ensure chrony is configured [${fail}${out}${end}]"
  fi
  echo "2.1.1.3, Ensure chrony is configured, $out" >> $report
  checks=$((checks+1))
  $slp

  rpm -qa xorg-x11* > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.2 Ensure X Window System is not installed [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.2 Ensure X Window System is not installed [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.2, Ensure X Window System is not installed, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled avahi-daemon > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.3 Ensure Avahi Server is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.3 Ensure Avahi Server is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.3, Ensure Avahi Server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled cups > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.4 Ensure CUPS is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.4 Ensure CUPS is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.4, Ensure CUPS is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled dhcpd > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.5 Ensure DHCP Server is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.5 Ensure DHCP Server is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.5, Ensure DHCP Server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled slapd > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.6 Ensure LDAP server is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.6 Ensure LDAP server is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.6, Ensure LDAP server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled nfs > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.7 Ensure NFS and RPC are not enabled [${fail}${out}${end}]"
  else
    sudo systemctl is-enabled nfs-server > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      local out="FAIL"
      echo -e "${bad} 2.1.7 Ensure NFS and RPC are not enabled [${fail}${out}${end}]"
    else
      sudo systemctl is-enabled rpcbind > /dev/null 2>&1
      if [ $? -eq 0 ]; then
        local out="FAIL"
        echo -e "${bad} 2.1.7 Ensure NFS and RPC are not enabled [${fail}${out}${end}]"
      else
        local out="PASS"
        echo -e "${good} 2.1.7 Ensure NFS and RPC are not enabled [${passed}${out}${end}]"
        counter=$((counter+1))
      fi
    fi
  fi
  echo "2.1.7, Ensure NFS and RPC are not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled named > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.8 Ensure DNS Server is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.8 Ensure DNS Server is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.8, Ensure DNS Server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled vsftpd > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.9 Ensure FTP Server is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.9 Ensure FTP Server is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.9, Ensure FTP Server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled httpd > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.10 Ensure HTTP server is not enabled [${fail}${out}${end}]"
  else
    sudo systemctl is-enabled apache2 > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      local out="FAIL"
      echo -e "${bad} 2.1.10 Ensure HTTP server is not enabled [${fail}${out}${end}]"
    else
      local out="PASS"
      echo -e "${good} 2.1.10 Ensure HTTP server is not enabled [${passed}${out}${end}]"
      counter=$((counter+1))
    fi
  fi
  echo "2.1.10, Ensure HTTP server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled dovecot > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.11 Ensure IMAP and POP3 server is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.11 Ensure IMAP and POP3 server is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.11, Ensure IMAP and POP3 server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled smb > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.12 Ensure Samba is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.12 Ensure Samba is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.12, Ensure Samba is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled squid > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.13 Ensure HTTP Proxy Server is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.13 Ensure HTTP Proxy Server is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.13, Ensure HTTP Proxy Server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled snmpd > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.14 Ensure SNMP Server is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.14 Ensure SNMP Server is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.14, Ensure SNMP Server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  netstat -an | grep LIST | grep ":25[[:space:]]" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.15 Ensure mail transfer agent is configured for local-only mode [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.15 Ensure mail transfer agent is configured for local-only mode [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.15, Ensure mail transfer agent is configured for local-only mode, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled ypserv > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.16 Ensure NIS Server is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.16 Ensure NIS Server is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.16, Ensure NIS Server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled rsh.socket > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.17 Ensure rsh server is not enabled [${fail}${out}${end}]"
  else
     sudo systemctl is-enabled rlogin.socket > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      local out="FAIL"
      echo -e "${bad} 2.1.17 Ensure rsh server is not enabled [${fail}${out}${end}]"
    else
      sudo systemctl is-enabled rexec.socket > /dev/null 2>&1
      if [ $? -eq 0 ]; then
        local out="FAIL"
        echo -e "${bad} 2.1.17 Ensure rsh server is not enabled [${fail}${out}${end}]"
      else
        local out="PASS"
        echo -e "${good} 2.1.17 Ensure rsh server is not enabled [${passed}${out}${end}]"
        counter=$((counter+1))
      fi
    fi
  fi
  echo "2.1.17, Ensure rsh server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled telnet.socket > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.18 Ensure telnet server is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.18 Ensure telnet server is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.18, Ensure telnet server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled tftp.socket > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.19 Ensure tftp server is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.19 Ensure tftp server is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.19, Ensure tftp server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled rsyncd > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.20 Ensure rsync service is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.20 Ensure rsync service is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.20, Ensure rsync service is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled ntalk > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.21 Ensure talk server is not enabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.1.21 Ensure talk server is not enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.1.21, Ensure talk server is not enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  rpm -q ypbind > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.2.1 Ensure NIS Client is not installed [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.2.1 Ensure NIS Client is not installed [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.2.1, Ensure NIS Client is not installed, $out" >> $report
  checks=$((checks+1))
  $slp

  rpm -q rsh > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.2.2 Ensure rsh client is not installed [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.2.2 Ensure rsh client is not installed [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.2.2, Ensure rsh client is not installed, $out" >> $report
  checks=$((checks+1))
  $slp

  rpm -q talk > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.2.3 Ensure talk client is not installed [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.2.3 Ensure talk client is not installed [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.2.3, Ensure talk client is not installed, $out" >> $report
  checks=$((checks+1))
  $slp

  rpm -q telnet > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.2.4 Ensure telnet client is not installed [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.2.4 Ensure telnet client is not installed [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.2.4, Ensure telnet client is not installed, $out" >> $report
  checks=$((checks+1))
  $slp

  rpm -q openldap-clients > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.2.5 Ensure LDAP client is not installed [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 2.2.5 Ensure LDAP client is not installed [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "2.2.5, Ensure LDAP client is not installed, $out" >> $report
  checks=$((checks+1))
  $slp

  echo -e "\n${good}3. Network Configuration${end}\n"

  local ipv4; local ipv6
  ipv4=$(sysctl net.ipv4.ip_forward | cut -d = -f 2 | sed 's/\s//g')
  ipv6=$(sysctl net.ipv6.conf.all.forwarding | cut -d = -f 2 | sed 's/\s//g')
  if [ "$ipv4" -eq 0 ] && [ "$ipv6" -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 3.1.1 Ensure IP forwarding is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.1.1 Ensure IP forwarding is disabled [${fail}${out}${end}]"
  fi
  echo "3.1.1, Ensure IP forwarding is disabled, $out" >> $report
  checks=$((checks+1))
  $slp

  local send_redirects; local send_redirects2
  send_redirects=$(sysctl net.ipv4.conf.all.send_redirects | cut -d = -f 2 | sed 's/\s//g')
  send_redirects2=$(sysctl net.ipv4.conf.default.send_redirects | cut -d = -f 2 | sed 's/\s//g')
  if [ "$send_redirects" -eq 0 ] && [ "$send_redirects2" -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 3.1.2 Ensure packet redirect sending is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.1.2 Ensure packet redirect sending is disabled [${fail}${out}${end}]"
  fi
  echo "3.1.2, Ensure packet redirect sending is disabled, $out" >> $report
  checks=$((checks+1))
  $slp

  local line;local var1;local var2;local var3;local var4;local var5;local var6;local var7;local var8;local var9;local var10;local var11;local var12;local var13
  var1=$(sysctl net.ipv4.conf.all.accept_source_route | cut -d = -f 2 | sed 's/\s//g')
  var2=$(sysctl net.ipv4.conf.default.accept_source_route | cut -d = -f 2 | sed 's/\s//g')
  var3=$(sysctl net.ipv4.conf.all.accept_source_route | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var4=$line
    var5=$line
  done < <(grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var6=$line
    var7=$line
  done < <(grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  var8=$(sysctl net.ipv6.conf.all.accept_source_route | cut -d = -f 2 | sed 's/\s//g')
  var9=$(sysctl net.ipv6.conf.default.accept_source_route | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var10=$line
    var11=$line
  done < <(grep "net\.ipv6\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var12=$line
    var13=$line
  done < <(grep "net\.ipv6\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  if [ "$var1" -eq 0 ] && [ "$var2" -eq 0 ]  && [ "$var3" -eq 0 ] && [ "$var4" -eq 0 ]  && [ "$var5" -eq 0 ] && [ "$var6" -eq 0 ]  && [ "$var7" -eq 0 ] && [ "$var8" -eq 0 ]  && [ "$var9" -eq 0 ] && [ "$var10" -eq 0 ]  && [ "$var11" -eq 0 ] && [ "$var12" -eq 0 ]  && [ "$var13" -eq 0 ];then
    local out="PASS"
    echo -e "${good} 3.2.1 Ensure source routed packets are not accepted [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.2.1 Ensure source routed packets are not accepted [${fail}${out}${end}]"
  fi
  echo "3.2.1, Ensure source routed packets are not accepted, $out" >> $report
  checks=$((checks+1))
  $slp

  var1=$(sysctl net.ipv4.conf.all.accept_redirects | cut -d = -f 2 | sed 's/\s//g')
  var2=$(sysctl net.ipv4.conf.default.accept_redirects | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var3=$line
    var4=$line
  done < <(grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var5=$line
    var6=$line
  done < <(grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  var7=$(sysctl net.ipv6.conf.all.accept_redirects | cut -d = -f 2 | sed 's/\s//g')
  var8=$(sysctl net.ipv6.conf.default.accept_redirects | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var9=$line
    var10=$line
  done < <(grep "net\.ipv6\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var11=$line
    var12=$line
  done < <(grep "net\.ipv6\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  if [ "$var1" -eq 0 ] && [ "$var2" -eq 0 ]  && [ "$var3" -eq 0 ] && [ "$var4" -eq 0 ]  && [ "$var5" -eq 0 ] && [ "$var6" -eq 0 ]  && [ "$var7" -eq 0 ] && [ "$var8" -eq 0 ]  && [ "$var9" -eq 0 ] && [ "$var10" -eq 0 ]  && [ "$var11" -eq 0 ] && [ "$var12" -eq 0 ];then
    local out="PASS"
    echo -e "${good} 3.2.2 Ensure ICMP redirects are not accepted [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.2.2 Ensure ICMP redirects are not accepted [${fail}${out}${end}]"
  fi
  echo "3.2.2, Ensure ICMP redirects are not accepted, $out" >> $report
  checks=$((checks+1))
  $slp

  var1=$(sysctl net.ipv4.conf.all.secure_redirects | cut -d = -f 2 | sed 's/\s//g')
  var2=$(sysctl net.ipv4.conf.default.secure_redirects | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var3=$line
    var4=$line
  done < <(grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var5=$line
    var6=$line
  done < <(grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  if [ "$var1" -eq 0 ] && [ "$var2" -eq 0 ]  && [ "$var3" -eq 0 ] && [ "$var4" -eq 0 ]  && [ "$var5" -eq 0 ] && [ "$var6" -eq 0 ];then
    local out="PASS"
    echo -e "${good} 3.2.3 Ensure secure ICMP redirects are not accepted [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.2.3 Ensure secure ICMP redirects are not accepted [${fail}${out}${end}]"
  fi
  echo "3.2.3, Ensure secure ICMP redirects are not accepted, $out" >> $report
  checks=$((checks+1))
  $slp

  var1=$(sysctl net.ipv4.conf.all.log_martians | cut -d = -f 2 | sed 's/\s//g')
  var2=$(sysctl net.ipv4.conf.default.log_martians | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var3=$line
    var4=$line
  done < <( grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var5=$line
    var6=$line
  done < <(grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  if [ "$var1" -eq 1 ] && [ "$var2" -eq 2 ]  && [ "$var3" -eq 0 ] && [ "$var4" -eq 0 ]  && [ "$var5" -eq 0 ] && [ "$var6" -eq 0 ];then
    local out="PASS"
    echo -e "${good} 3.2.4 Ensure suspicious packets are logged [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.2.4 Ensure suspicious packets are logged [${fail}${out}${end}]"
  fi
  echo "3.2.4, Ensure suspicious packets are logged, $out" >> $report
  checks=$((checks+1))
  $slp

  var1=$(sysctl net.ipv4.icmp_echo_ignore_broadcasts | cut -d = -f 2 | sed 's/\s//g')
  while IFS= read -r line
  do
    var2=$line
    var3=$line
  done < <(grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  if [ "$var1" -eq 1 ] && [ "$var2" -eq 1 ] && [ "$var3" -eq 1 ];then
    local out="PASS"
    echo -e "${good} 3.2.5 Ensure broadcast ICMP requests are ignored [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.2.5 Ensure broadcast ICMP requests are ignored [${fail}${out}${end}]"
  fi
  echo "3.2.5, Ensure broadcast ICMP requests are ignored, $out" >> $report
  checks=$((checks+1))
  $slp

  var1=$(sysctl net.ipv4.icmp_ignore_bogus_error_responses | cut -d = -f 2 | sed 's/\s//g')
  while IFS= read -r line
  do
    var2=$line
    var3=$line
  done < <(grep "net\.ipv4\.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  if [ "$var1" -eq 1 ] && [ "$var2" -eq 1 ] && [ "$var3" -eq 1 ];then
    local out="PASS"
    echo -e "${good} 3.2.6 Ensure bogus ICMP responses are ignored [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.2.6 Ensure bogus ICMP responses are ignored [${fail}${out}${end}]"
  fi
  echo "3.2.6, Ensure bogus ICMP responses are ignored, $out" >> $report
  checks=$((checks+1))
  $slp

  var1=$(sysctl net.ipv4.conf.all.rp_filter | cut -d = -f 2 | sed 's/\s//g')
  var2=$(sysctl net.ipv4.conf.default.rp_filter | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var3=$line
    var4=$line
  done < <(grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var5=$line
    var6=$line
  done < <(grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  if [ "$var1" -eq 1 ] && [ "$var2" -eq 1 ] && [ "$var3" -eq 1 ] && [ "$var4" -eq 1 ] && [ "$var5" -eq 1 ] && [ "$var6" -eq 1 ];then
    local out="PASS"
    echo -e "${good} 3.2.7 Ensure Reverse Path Filtering is enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.2.7 Ensure Reverse Path Filtering is enabled [${fail}${out}${end}]"
  fi
  echo "3.2.7, Ensure Reverse Path Filtering is enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  var1=$(sysctl net.ipv4.tcp_syncookies | cut -d = -f 2 | sed 's/\s//g')
  while IFS= read -r line
  do
    var2=$line
    var3=$line
  done < <(grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  if [ "$var1" -eq 1 ] && [ "$var2" -eq 1 ] && [ "$var3" -eq 1 ];then
    local out="PASS"
    echo -e "${good} 3.2.8 Ensure TCP SYN Cookies is enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.2.8 Ensure TCP SYN Cookies is enabled [${fail}${out}${end}]"
  fi
  echo "3.2.8, Ensure TCP SYN Cookies is enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  var1=$(sysctl net.ipv6.conf.all.accept_ra | cut -d = -f 2 | sed 's/\s//g')
  var2=$(sysctl net.ipv6.conf.default.accept_ra | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var3=$line
    var4=$line
  done < <(grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  while IFS= read -r line
  do
    var5=$line
    var6=$line
  done < <(grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/* | cut -d = -f 2 | sed 's/\s//g')

  if [ "$var1" -eq 0 ] && [ "$var2" -eq 0 ] && [ "$var3" -eq 0 ] && [ "$var4" -eq 0 ] && [ "$var5" -eq 0 ] && [ "$var6" -eq 0 ];then
    local out="PASS"
    echo -e "${good} 3.2.9 Ensure IPv6 router advertisements are not accepted [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.2.9 Ensure IPv6 router advertisements are not accepted [${fail}${out}${end}]"
  fi
  echo "3.2.9, Ensure IPv6 router advertisements are not accepted, $out" >> $report
  checks=$((checks+1))
  $slp

  rpm -q tcp_wrappers > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 3.3.1 Ensure TCP Wrappers is installed [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.3.1 Ensure TCP Wrappers is installed [${fail}${out}${end}]"
  fi
  echo "3.3.1, Ensure TCP Wrappers is installed, $out" >> $report
  checks=$((checks+1))
  $slp

  grep '#' -v /etc/hosts.allow | grep 'ALL:' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 3.3.2 Ensure /etc/hosts.allow is configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.3.2 Ensure /etc/hosts.allow is configured [${fail}${out}${end}]"
  fi
  echo "3.3.2, Ensure /etc/hosts.allow is configured, $out" >> $report
  checks=$((checks+1))
  $slp

  grep '#' -v /etc/hosts.deny | grep 'ALL:' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 3.3.3 Ensure /etc/hosts.deny is configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.3.3 Ensure /etc/hosts.deny is configured [${fail}${out}${end}]"
  fi
  echo "3.3.3, Ensure /etc/hosts.deny is configured, $out" >> $report
  checks=$((checks+1))
  $slp

  uid=$(stat /etc/hosts.allow | grep 'Uid' | awk '{print $5}' | tr -d '/')
  gid=$(stat /etc/hosts.allow | grep 'Uid' | awk '{print $9}' | tr -d '/')
  if [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 3.3.4 Ensure permissions on /etc/hosts.allow are configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.3.4 Ensure permissions on /etc/hosts.allow are configured [${fail}${out}${end}]"
  fi
  echo "3.3.4, Ensure permissions on /etc/hosts.allow are configured, $out" >> $report
  checks=$((checks+1))
  $slp

  uid=$(stat /etc/hosts.deny | grep 'Uid' | awk '{print $5}' | tr -d '/')
  gid=$(stat /etc/hosts.deny | grep 'Uid' | awk '{print $9}' | tr -d '/')
  if [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 3.3.5 Ensure permissions on /etc/hosts.deny are configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.3.5 Ensure permissions on /etc/hosts.deny are configured [${fail}${out}${end}]"
  fi
  echo "3.3.5, Ensure permissions on /etc/hosts.deny are configured, $out" >> $report
  checks=$((checks+1))
  $slp

  modprobe -n -v dccp > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 3.4.1 Ensure DCCP is disabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 3.4.1 Ensure DCCP is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "3.4.1, Ensure DCCP is disabled, $out" >> $report
  checks=$((checks+1))
  $slp

  modprobe -n -v sctp > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 3.4.2 Ensure SCTP is disabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 3.4.2 Ensure SCTP is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "3.4.2, Ensure SCTP is disabled, $out" >> $report
  checks=$((checks+1))
  $slp

  modprobe -n -v rds > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 3.4.3 Ensure RDS is disabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 3.4.3 Ensure RDS is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "3.4.3, Ensure RDS is disabled, $out" >> $report
  checks=$((checks+1))
  $slp

  modprobe -n -v tipc > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 3.4.4 Ensure TIPC is disabled [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 3.4.4 Ensure TIPC is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "3.4.4, Ensure TIPC is disabled, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo iptables -L | grep -E "INPUT|OUTPUT|FORWARD" | grep -E "DROP|REJECT" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 3.5.1.1 Ensure default deny firewall policy [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 3.5.1.1 Ensure default deny firewall policy [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "3.5.1.1, Ensure default deny firewall policy, $out" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${bad} 3.5.1.2 Ensure loopback traffic is configured [${fail}! MANUAL !${end}]"
  echo "3.5.1.2, Ensure loopback traffic is configured, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${bad} 3.5.1.3 Ensure outbound and established connections are configured  [${fail}! MANUAL !${end}]"
  echo "3.5.1.3, Ensure outbound and established connections are configured , MANUAL" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${bad} 3.5.1.4 Ensure firewall rules exist for all open ports [${fail}! MANUAL !${end}]"
  echo "3.5.1.4, Ensure firewall rules exist for all open ports, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  sudo ip6tables -L | grep -E "INPUT|OUTPUT|FORWARD" | grep -E "DROP|REJECT" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 3.5.2.1 Ensure IPv6 default deny firewall policy [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 3.5.2.1 Ensure IPv6 default deny firewall policy [${passed}${out}${end}]"
    counter=$((counter+1))
  fi
  echo "3.5.2.1, Ensure IPv6 default deny firewall policy, $out" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${bad} 3.5.2.2 Ensure IPv6 loopback traffic is configured [${fail}! MANUAL !${end}]"
  echo "3.5.2.2, Ensure IPv6 loopback traffic is configured, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${bad} 3.5.2.3 Ensure IPv6 outbound and established connections are configured  [${fail}! MANUAL !${end}]"
  echo "3.5.2.3, Ensure IPv6 outbound and established connections are configured, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${bad} 3.5.2.4 Ensure IPv6 firewall rules exist for all open ports [${fail}! MANUAL !${end}]"
  echo "3.5.2.4, Ensure IPv6 firewall rules exist for all open ports. MANUAL" >> $report
  checks=$((checks+1))
  $slp

  rpm -q iptables > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 3.5.3 Ensure iptables is installed [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 3.5.3 Ensure iptables is installed [${fail}${out}${end}]"
  fi
  echo "3.5.3, Ensure iptables is installed, $out" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${bad} 3.6 Disable IPv6 [${fail}! MANUAL !${end}]"
  echo "3.6, Disable IPv63.6 Disable IPv6, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  echo -e "\n${good}4. Logging and Auditing${end}\nConfiguring System Accounting (auditID)"

  sudo service auditd reload > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 4.1 Configure System Accounting. auditid appears to be uninstalled. [${fail}${out}${end}]"
  else
    local out="PASS"
    echo -e "${good} 4.1 Configure System Accounting [${passed}${out}${end}]"
    counter=$((counter+1))
  fi

  grep "max_log_file" /etc/audit/auditd.conf > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.1.1 Ensure audit log storage size is configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.1.1 Ensure audit log storage size is configured [${fail}${out}${end}]"
  fi
  echo "4.1.1.1, Ensure audit log storage size is configured, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "space_left_action" /etc/audit/auditd.conf > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    grep "action_mail_acct" /etc/audit/auditd.conf > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      grep "admin_space_left_action" /etc/audit/auditd.conf > /dev/null 2>&1
      if [ $? -eq 0 ]; then
        local out="PASS"
        echo -e "${good} 4.1.1.2 Ensure system is disabled when audit logs are full [${passed}${out}${end}]"
        counter=$((counter+1))
      else
        local out="FAIL"
        echo -e "${bad} 4.1.1.2 Ensure system is disabled when audit logs are full [${fail}${out}${end}]"
      fi
    else
      local out="FAIL"
      echo -e "${bad} 4.1.1.2 Ensure system is disabled when audit logs are full [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 4.1.1.2 Ensure system is disabled when audit logs are full [${fail}${out}${end}]"
  fi
  echo "4.1.1.2, Ensure system is disabled when audit logs are full, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "max_log_file_action" /etc/audit/auditd.conf > /dev/null 2>&1 | grep "keep_logs" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.1.3 Ensure audit logs are not automatically deleted [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.1.3 Ensure audit logs are not automatically deleted [${fail}${out}${end}]"
  fi
  echo "4.1.1.3, Ensure audit logs are not automatically deleted, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled auditd > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.2 Ensure auditd service is enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.2 Ensure auditd service is enabled [${fail}${out}${end}]"
  fi
  echo "4.1.2, Ensure auditd service is enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  if test -f "/boot/grub2/grub.cfg"; then
    grep "^\s*linux" /boot/grub2/grub.cfg | grep 'audit=1'
    if [ $? -eq 0 ];then
      local out="PASS"
      echo -e "${good} 4.1.3 Ensure auditing for processes that start prior to auditd is enabled [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 4.1.3 Ensure auditing for processes that start prior to auditd is enabled [${fail}${out}${end}]"
    fi
  elif test -f "/boot/grub/grub.cfg"; then
    grep "^\s*linux" /boot/grub/grub.cfg | grep 'audit=1'
    if [ $? -eq 0 ];then
      local out="PASS"
      echo -e "${good} 4.1.3 Ensure auditing for processes that start prior to auditd is enabled [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 4.1.3 Ensure auditing for processes that start prior to auditd is enabled [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 4.1.3 Ensure auditing for processes that start prior to auditd is enabled [${fail}${out}${end}]"
  fi

  grep "time-change" /etc/audit/audit.rules > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.4 Ensure events that modify date and time information are collected [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.4 Ensure events that modify date and time information are collected [${fail}${out}${end}]"
  fi
  echo "4.1.4, Ensure events that modify date and time information are collected, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "identity" /etc/audit/audit.rules > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.5 Ensure events that modify user/group information are collected [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.5 Ensure events that modify user/group information are collected [${fail}${out}${end}]"
  fi
  echo "4.1.5, Ensure events that modify user/group information are collected, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "system-locale" /etc/audit/audit.rules > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.6 Ensure events that modify the systems network environment are collected [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.6 Ensure events that modify the systems network environment are collected [${fail}${out}${end}]"
  fi
  echo "4.1.6, Ensure events that modify the systems network environment are collected, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "MAC-policy" /etc/audit/audit.rules > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.7 Ensure events that modify the systems Mandatory Access Controls are collected [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.7 Ensure events that modify the systems Mandatory Access Controls are collected [${fail}${out}${end}]"
  fi
  echo "4.1.7, Ensure events that modify the systems Mandatory Access Controls are collected, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "logins" /etc/audit/audit.rules > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.8 Ensure login and logout events are collected [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.8 Ensure login and logout events are collected [${fail}${out}${end}]"
  fi
  echo "4.1.8, Ensure login and logout events are collected, $out" >> $report
  checks=$((checks+1))
  $slp

   grep "session" /etc/audit/audit.rules > /dev/null 2>&1
   if [ $? -eq 0 ]; then
    grep logins /etc/audit/audit.rules
    if [ $? -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 4.1.9 Ensure session initiation information is collected [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 4.1.9 Ensure session initiation information is collected [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 4.1.9 Ensure session initiation information is collected [${fail}${out}${end}]"
  fi
  echo "4.1.9, Ensure session initiation information is collected, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "perm_mod" /etc/audit/audit.rules > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.10 Ensure discretionary access control permission modification events are collected [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.10 Ensure discretionary access control permission modification events are collected [${fail}${out}${end}]"
  fi
  echo "4.1.10, Ensure discretionary access control permission modification events are collected, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "access" /etc/audit/audit.rules > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected [${fail}${out}${end}]"
  fi
  echo "4.1.11, Ensure unsuccessful unauthorized file access attempts are collected, $out" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${good} 4.1.12 Ensure use of privileged commands is collected [${passed}! MANUAL !${end}]"
  counter=$((counter+1))
  echo "4.1.12, Ensure use of privileged commands is collected, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  grep "mounts" /etc/audit/audit.rules > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.13 Ensure successful file system mounts are collected [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.13 Ensure successful file system mounts are collected [${fail}${out}${end}]"
  fi
  echo "4.1.13, Ensure successful file system mounts are collected, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "delete" /etc/audit/audit.rules > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.14 Ensure file deletion events by users are collected [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.14 Ensure file deletion events by users are collected [${fail}${out}${end}]"
  fi
  echo "4.1.14, Ensure file deletion events by users are collected, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "scope" /etc/audit/audit.rules > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.15 Ensure changes to system administration scope sudoers is collected [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.15 Ensure changes to system administration scope sudoers is collected [${fail}${out}${end}]"
  fi
  echo "4.1.15, Ensure changes to system administration scope sudoers is collected, $out" >> $report
  checks=$((checks+1))
  $slp

  grep actions /etc/audit/audit.rules > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.16 Ensure system administrator actions (sudolog) are collected [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.16 Ensure system administrator actions (sudolog) are collected [${fail}${out}${end}]"
  fi
  echo "4.1.16, Ensure system administrator actions (sudolog) are collected, $out" >> $report
  checks=$((checks+1))
  $slp

  grep modules /etc/audit/audit.rules > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.17 Ensure kernel module loading and unloading is collected [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.17 Ensure kernel module loading and unloading is collected [${fail}${out}${end}]"
  fi
  echo "4.1.17, Ensure kernel module loading and unloading is collected, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "^\s*[^#]" /etc/audit/audit.rules > /dev/null 2>&1 | grep '-e 2' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.1.18 Ensure the audit configuration is immutable [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.1.18 Ensure the audit configuration is immutable [${fail}${out}${end}]"
  fi
  echo "4.1.18, Ensure the audit configuration is immutable, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled rsyslog > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.2.1.1 Ensure rsyslog Service is enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.2.1.1 Ensure rsyslog Service is enabled [${fail}${out}${end}]"
  fi
  echo "4.2.1.1, Ensure rsyslog Service is enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  var1=$(ls -l /var/log | head -1 | awk '{print $2}')
  if [ $var1 -gt 0 ];then
    local out="PASS"
    echo -e "${good} 4.2.1.2 Ensure logging is configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.2.1.2 Ensure logging is configured [${fail}${out}${end}]"
  fi
  echo "4.2.1.2, Ensure logging is configured, $out" >> $report
  checks=$((checks+1))
  $slp

  var1=$(grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf | cut -d ' ' -f 2)
  if [ $var1 -eq 0640 ];then
    local out="PASS"
    echo -e "${good} 4.2.1.3 Ensure rsyslog default file permissions configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.2.1.3 Ensure rsyslog default file permissions configured [${fail}${out}${end}]"
  fi
  echo "4.2.1.3, Ensure rsyslog default file permissions configured $out" >> $report
  checks=$((checks+1))
  $slp

  grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host [${fail}${out}${end}]"
  fi
  echo "4.2.1.4, Ensure rsyslog is configured to send logs to a remote log host, $out" >> $report
  checks=$((checks+1))
  $slp

  grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts [${fail}${out}${end}]"
  fi
  echo "4.2.1.5, Ensure remote rsyslog messages are only accepted on designated log hosts, $out" >> $report
  checks=$((checks+1))
  $slp

  sudo systemctl is-enabled syslog-ng > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.2.2.1 Ensure syslog-ng service is enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.2.2.1 Ensure syslog-ng service is enabled [${fail}${out}${end}]"
  fi
  echo "4.2.2.1, Ensure syslog-ng service is enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  var1=$(ls -l /var/log | head -1 | awk '{print $2}')
  if [ "$var1" -gt 0 ];then
    local out="PASS"
    echo -e "${good} 4.2.2.2 Ensure logging is configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.2.2.2 Ensure logging is configured [${fail}${out}${end}]"
  fi
  echo "4.2.2.2, Ensure logging is configured, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "^options" /etc/syslog-ng/syslog-ng.conf > /dev/null 2>&1 | grep '0640' > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.2.2.3 Ensure syslog-ng default file permissions configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.2.2.3 Ensure syslog-ng default file permissions configured [${fail}${out}${end}]"
  fi
  echo "4.2.2.3, Ensure syslog-ng default file permissions configured, $out" >> $report
  checks=$((checks+1))
  $slp

  grep "^*.*[^I][^I]*@" /etc/syslog-ng/syslog-ng.conf > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host [${fail}${out}${end}]"
  fi
  echo "4.2.2.4, Ensure syslog-ng is configured to send logs to a remote log host, $out" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${good} 4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts [${passed}! MANUAL !${end}]"
  counter=$((counter+1))
  echo "4.2.2.5, Ensure remote syslog-ng messages are only accepted on designated log hosts, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  rpm -q rsyslog > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    rpm -q syslog-ng > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 4.2.3 Ensure rsyslog or syslog-ng is installed [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
    echo -e "${bad} 4.2.3 Ensure rsyslog or syslog-ng is installed [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 4.2.3 Ensure rsyslog or syslog-ng is installed [${fail}${out}${end}]"
  fi
  echo "4.2.3, Ensure rsyslog or syslog-ng is installed, $out" >> $report
  checks=$((checks+1))
  $slp

  local archivo;local other;local groups;local cother;local cgroups
  cother=0;cgroups=0
  while IFS= read -r line
  do
    archivo=$line
    other=$(stat -c "%a" $line | cut -c 3)
    groups=$(stat -c "%a" $line | cut -c 2)
    if [ $other -gt 0 ];then
        cother=$((cother+1))
    fi
    if [ $groups -gt 4 ];then
        cgroups=$((cgroups+1))
    fi
  done < <(find /var/log -type f 2>/dev/null)
  if [ $cother -eq 0 ] && [ $cgroups -eq 0 ];then
    local out="PASS"
    echo -e "${good} 4.2.4 Ensure permissions on all logfiles are configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 4.2.4 Ensure permissions on all logfiles are configured [${fail}${out}${end}]"
  fi
  echo "4.2.4, Ensure permissions on all logfiles are configured, $out" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${good} 4.3 Ensure logrotate is configured [${passed}! MANUAL !${end}]"
  counter=$((counter+1))
  echo "4.3, Ensure logrotate is configured, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  echo -e "\n${good}5 Access, Authentication and Authorization${end}\n5.1 Configure cron"

  systemctl is-enabled crond > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="PASS"
    echo -e "${good} 5.1.1 Ensure cron daemon is enabled [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 5.1.1 Ensure cron daemon is enabled [${fail}${out}${end}]"
  fi
  echo "5.1.1, Ensure cron daemon is enabled, $out" >> $report
  checks=$((checks+1))
  $slp

  uid=$(stat /etc/crontab | grep 'Uid' | awk '{print $5}' | tr -d '/')
  gid=$(stat /etc/crontab | grep 'Uid' | awk '{print $9}' | tr -d '/')
  if [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ]; then
    other=$(stat -c "%a" /etc/crontab | cut -c 3)
    groups=$(stat -c "%a" /etc/crontab | cut -c 2)
    if [ "$other" -eq 0 ] && [ "$groups" -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 5.1.2 Ensure permissions on /etc/crontab are configured [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 5.1.2 Ensure permissions on /etc/crontab are configured [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 5.1.2 Ensure permissions on /etc/crontab are configured [${fail}${out}${end}]"
  fi
  echo "5.1.2, Ensure permissions on /etc/crontab are configured, $out" >> $report
  checks=$((checks+1))
  $slp

  uid=$(stat /etc/cron.hourly | grep 'Uid' | awk '{print $5}' | tr -d '/')
  gid=$(stat /etc/cron.hourly | grep 'Uid' | awk '{print $9}' | tr -d '/')
  if [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ]; then
    other=$(stat -c "%a" /etc/cron.hourly | cut -c 3)
    groups=$(stat -c "%a" /etc/cron.hourly | cut -c 2)
    if [ "$other" -eq 0 ] && [ "$groups" -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 5.1.3 Ensure permissions on /etc/cron.hourly are configured [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 5.1.3 Ensure permissions on /etc/cron.hourly are configured [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 5.1.3 Ensure permissions on /etc/cron.hourly are configured [${fail}${out}${end}]"
  fi
  echo "5.1.3, Ensure permissions on /etc/cron.hourly are configured, $out" >> $report
  checks=$((checks+1))
  $slp

  uid=$(stat /etc/cron.daily | grep 'Uid' | awk '{print $5}' | tr -d '/')
  gid=$(stat /etc/cron.daily | grep 'Uid' | awk '{print $9}' | tr -d '/')
  if [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ]; then
    other=$(stat -c "%a" /etc/cron.daily | cut -c 3)
    groups=$(stat -c "%a" /etc/cron.daily | cut -c 2)
    if [ "$other" -eq 0 ] && [ "$groups" -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 5.1.4 Ensure permissions on /etc/cron.daily are configured [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 5.1.4 Ensure permissions on /etc/cron.daily are configured [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 5.1.4 Ensure permissions on /etc/cron.daily are configured [${fail}${out}${end}]"
  fi
  echo "5.1.4, Ensure permissions on /etc/cron.daily are configured, $out" >> $report
  checks=$((checks+1))
  $slp

  uid=$(stat /etc/cron.weekly | grep 'Uid' | awk '{print $5}' | tr -d '/')
  gid=$(stat /etc/cron.weekly | grep 'Uid' | awk '{print $9}' | tr -d '/')
  if [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ]; then
    other=$(stat -c "%a" /etc/cron.weekly | cut -c 3)
    groups=$(stat -c "%a" /etc/cron.weekly | cut -c 2)
    if [ "$other" -eq 0 ] && [ "$groups" -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 5.1.5 Ensure permissions on /etc/cron.weekly are configured [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 5.1.5 Ensure permissions on /etc/cron.weekly are configured [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 5.1.5 Ensure permissions on /etc/cron.weekly are configured [${fail}${out}${end}]"
  fi
  echo "5.1.5, Ensure permissions on /etc/cron.weekly are configured, $out" >> $report
  checks=$((checks+1))
  $slp

  uid=$(stat /etc/cron.monthly | grep 'Uid' | awk '{print $5}' | tr -d '/')
  gid=$(stat /etc/cron.monthly | grep 'Uid' | awk '{print $9}' | tr -d '/')
  if [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ]; then
    other=$(stat -c "%a" /etc/cron.monthly | cut -c 3)
    groups=$(stat -c "%a" /etc/cron.monthly | cut -c 2)
    if [ "$other" -eq 0 ] && [ "$groups" -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 5.1.6 Ensure permissions on /etc/cron.monthly are configured [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 5.1.6 Ensure permissions on /etc/cron.monthly are configured [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 5.1.6 Ensure permissions on /etc/cron.monthly are configured [${fail}${out}${end}]"
  fi
  echo "5.1.6, Ensure permissions on /etc/cron.monthly are configured, $out" >> $report
  checks=$((checks+1))
  $slp

  uid=$(stat /etc/cron.d | grep 'Uid' | awk '{print $5}' | tr -d '/')
  gid=$(stat /etc/cron.d | grep 'Uid' | awk '{print $9}' | tr -d '/')
  if [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ]; then
    other=$(stat -c "%a" /etc/cron.d | cut -c 3)
    groups=$(stat -c "%a" /etc/cron.d | cut -c 2)
    if [ "$other" -eq 0 ] && [ "$groups" -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 5.1.7 Ensure permissions on /etc/cron.d are configured [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 5.1.7 Ensure permissions on /etc/cron.d are configured [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 5.1.7 Ensure permissions on /etc/cron.d are configured [${fail}${out}${end}]"
  fi
  echo "5.1.7, Ensure permissions on /etc/cron.d are configured, $out" >> $report
  checks=$((checks+1))
  $slp

  if test -f "/etc/cron.deny"; then
    local out="FAIL"
    echo -e "${bad} 5.1.7 Ensure permissions on /etc/cron.d are configured [${fail}${out}${end}]"
  else
    if test -f "/etc/at.deny"; then
      uid=$(stat /etc/cron.allow | grep 'Uid' | awk '{print $5}' | tr -d '/')
      gid=$(stat /etc/cron.allow | grep 'Uid' | awk '{print $9}' | tr -d '/')
      if [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ]; then
        other=$(stat -c "%a" /etc/cron.allow | cut -c 3)
        groups=$(stat -c "%a" /etc/cron.allow | cut -c 2)
        if [ "$other" -eq 0 ] && [ "$groups" -eq 0 ]; then
          uid=$(stat /etc/at.allow | grep 'Uid' | awk '{print $5}' | tr -d '/')
          gid=$(stat /etc/at.allow | grep 'Uid' | awk '{print $9}' | tr -d '/')
          if [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ]; then
            other=$(stat -c "%a" /etc/at.allow | cut -c 3)
            groups=$(stat -c "%a" /etc/at.allow | cut -c 2)
            if [ "$other" -eq 0 ] && [ "$groups" -eq 0 ]; then
              local out="PASS"
              echo -e "${good} 5.1.8 Ensure at/cron is restricted to authorized users [${passed}${out}${end}]"
              counter=$((counter+1))
            else
              local out="FAIL"
              echo -e "${bad} 5.1.8 Ensure at/cron is restricted to authorized users [${fail}${out}${end}]"
            fi
          else
            local out="FAIL"
            echo -e "${bad} 5.1.8 Ensure at/cron is restricted to authorized users [${fail}${out}${end}]"
          fi
        else
          local out="FAIL"
          echo -e "${bad} 5.1.8 Ensure at/cron is restricted to authorized users [${fail}${out}${end}]"
        fi
      else
        local out="FAIL"
        echo -e "${bad} 5.1.8 Ensure at/cron is restricted to authorized users [${fail}${out}${end}]"
      fi
    else
      local out="FAIL"
      echo -e "${bad} 5.1.8 Ensure at/cron is restricted to authorized users [${fail}${out}${end}]"
    fi
  fi
  echo "5.1.8, Ensure at/cron is restricted to authorized users, $out" >> $report
  checks=$((checks+1))
  $slp

  uid=$(stat /etc/ssh/sshd_config | grep 'Uid' | awk '{print $5}' | tr -d '/')
  gid=$(stat /etc/ssh/sshd_config | grep 'Uid' | awk '{print $9}' | tr -d '/')
  if [ "$uid" -eq 0 ] && [ "$gid" -eq 0 ]; then
    other=$(stat -c "%a" /etc/ssh/sshd_config | cut -c 3)
    groups=$(stat -c "%a" /etc/ssh/sshd_config | cut -c 2)
    if [ "$other" -eq 0 ] && [ "$groups" -eq 0 ]; then
      local out="PASS"
      echo -e "${good} 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured [${passed}${out}${end}]"
      counter=$((counter+1))
    else
      local out="FAIL"
      echo -e "${bad} 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured [${fail}${out}${end}]"
    fi
  else
    local out="FAIL"
    echo -e "${bad} 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured [${fail}${out}${end}]"
  fi
  echo "5.2.1, Ensure permissions on /etc/ssh/sshd_config are configured, $out" >> $report
  checks=$((checks+1))
  $slp

  while IFS= read -r line
  do
    uid=$(stat $line | grep 'Uid' | awk '{print $5}' | tr -d '/')
    gid=$(stat $line | grep 'Uid' | awk '{print $9}' | tr -d '/')
    archivo=$line
    other=$(stat -c "%a" $line | cut -c 3)
    groups=$(stat -c "%a" $line | cut -c 2)
    count=$((uid+gid+other+groups))
  done < <(find /etc/ssh -xdev -type f -name 'ssh_host_*_key')
  if [ $count -eq 0 ];then
    local out="PASS"
    echo -e "${good} 5.2.2 Ensure permissions on SSH private host key files are configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 5.2.2 Ensure permissions on SSH private host key files are configured [${fail}${out}${end}]"
  fi
  echo "5.2.2, Ensure permissions on SSH private host key files are configured, $out" >> $report
  checks=$((checks+1))
  $slp

  while IFS= read -r line
  do
    uid=$(stat "$line" | grep 'Uid' | awk '{print $5}' | tr -d '/')
    gid=$(stat "$line" | grep 'Uid' | awk '{print $9}' | tr -d '/')
    archivo=$line
    other=$(stat -c "%a" "$line" | cut -c 3)
    groups=$(stat -c "%a" "$line" | cut -c 2)
    count=$((uid+gid+other+groups))
  done < <(find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub')
  if [ $count -eq 0 ];then
    local out="PASS"
    echo -e "${good} 5.2.3 Ensure permissions on SSH public host key files are configured [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 5.2.3 Ensure permissions on SSH public host key files are configured [${fail}${out}${end}]"
  fi
  echo "5.2.3, Ensure permissions on SSH public host key files are configured, $out" >> $report
  checks=$((checks+1))
  $slp

  echo -e "${good} 5.2.4 Ensure SSH Protocol is set to 2 [${passed}! MANUAL !${end}]"
  counter=$((counter+1))
  echo "5.2.4, Ensure SSH Protocol is set to 2, MANUAL" >> $report
  checks=$((checks+1))
  $slp

  loglevel=$(sshd -T | grep loglevel | cut -d ' ' -f 2)
  if [ "$loglevel" == "VERBOSE" ] || [ "$loglevel" == "INFO" ];then
    local out="PASS"
    echo -e "${good} 5.2.5 Ensure SSH LogLevel is appropriate [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 5.2.5 Ensure SSH LogLevel is appropriate [${fail}${out}${end}]"
  fi
  echo "5.2.5, Ensure SSH LogLevel is appropriate, $out" >> $report
  checks=$((checks+1))
  $slp

  x11forward=$(sshd -T | grep x11forwarding | cut -d ' ' -f 2)
  if [ "$x11forward" == "no" ];then
    local out="PASS"
    echo -e "${good} 5.2.6 Ensure SSH X11 forwarding is disabled [${passed}${out}${end}]"
    counter=$((counter+1))
  else
    local out="FAIL"
    echo -e "${bad} 5.2.6 Ensure SSH X11 forwarding is disabled [${fail}${out}${end}]"
  fi
  echo "5.2.6, Ensure SSH X11 forwarding is disabled, $out" >> $report
  checks=$((checks+1))
  $slp





















  echo $checks
  echo $counter


}

banner
initCSV
checkL1


