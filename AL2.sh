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
    gid=$(stat /boot/grub2/grub.cfg | grep 'Uid' | awk '{print $5}' | tr -d '/')
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
    gid=$(stat /boot/grub/grub.cfg | grep 'Uid' | awk '{print $5}' | tr -d '/')
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
  if [ "$alr" -eq 2 ]; then
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

  #1.5.3 Ensure prelink is disabled
  # rpm -q prelink

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

  #1.6.1.4 Ensure SETroubleshoot is not installed
  #rpm -q setroubleshoot

  #1.6.1.5 Ensure the MCS Translation Service (mcstrans) is not installed
  #rpm -q mcstrans

  #1.6.1.6 Ensure no unconfined daemons exist
  #ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'

  #1.6.2 Ensure SELinux is installed
  #rpm -q libselinux

  echo -e "\n${good}1.7 Warning Banners${end}\n"

  #1.7.1.1 Ensure message of the day is configured properly
  #cat /etc/motd
  #egrep -i '(\\v|\\r|\\m|\\s|Amazon)' /etc/motd

  #1.7.1.2 Ensure local login warning banner is configured properly
  #cat /etc/issue
  #egrep -i '(\\v|\\r|\\m|\\s|Amazon)' /etc/issue

  #1.7.1.3 Ensure remote login warning banner is configured properly
  #cat /etc/issue.net
  #egrep -i '(\\v|\\r|\\m|\\s|Amazon)' /etc/issue.net

  if test -f "/etc/motd"; then
    uid=$(stat /etc/motd | grep 'Uid' | awk '{print $5}' | tr -d '/')
    gid=$(stat /etc/motd | grep 'Uid' | awk '{print $5}' | tr -d '/')
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
    gid=$(stat /etc/issue | grep 'Uid' | awk '{print $5}' | tr -d '/')
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
    gid=$(stat /etc/issue.net | grep 'Uid' | awk '{print $5}' | tr -d '/')
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

  #1.8 Ensure updates, patches, and additional security software are installed
  #yum check-update --security

  echo -e "\n${good}2. Services${end}\n2.1 Special Purpose Services\n"

  #2.1.1.1 Ensure time synchronization is in use
  # rpm -q ntp
# rpm -q chrony

  #2.1.1.2 Ensure ntp is configured
  #grep "^restrict" /etc/ntp.conf
  # grep "^(server|pool)" /etc/ntp.conf
  # grep "^OPTIONS" /etc/sysconfig/ntpd
  # grep "^ExecStart" /usr/lib/systemd/system/ntpd.service

  #2.1.1.3 Ensure chrony is configured
  #grep "^(server|pool)" /etc/chrony.conf
  #grep ^OPTIONS /etc/sysconfig/chronyd

  #2.1.2 Ensure X Window System is not installed
  # rpm -qa xorg-x11*

  systemctl is-enabled avahi-daemon > /dev/null 2>&1
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

  systemctl is-enabled cups > /dev/null 2>&1
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

  systemctl is-enabled dhcpd > /dev/null 2>&1
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

  systemctl is-enabled slapd > /dev/null 2>&1
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

  systemctl is-enabled nfs > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.7 Ensure NFS and RPC are not enabled [${fail}${out}${end}]"
  else
    systemctl is-enabled nfs-server > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      local out="FAIL"
      echo -e "${bad} 2.1.7 Ensure NFS and RPC are not enabled [${fail}${out}${end}]"
    else
      systemctl is-enabled rpcbind > /dev/null 2>&1
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

  systemctl is-enabled named > /dev/null 2>&1
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

  systemctl is-enabled vsftpd > /dev/null 2>&1
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

  systemctl is-enabled httpd > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    local out="FAIL"
    echo -e "${bad} 2.1.10 Ensure HTTP server is not enabled [${fail}${out}${end}]"
  else
    systemctl is-enabled apache2 > /dev/null 2>&1
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

  systemctl is-enabled dovecot > /dev/null 2>&1
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

  systemctl is-enabled smb > /dev/null 2>&1
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



  echo $checks
  echo $counter


}

banner
initCSV
checkL1


