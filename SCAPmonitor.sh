#!bin/bash

# SCAPmonitor allows continuous monitoring of a Ubuntu 20.04 system, using
# OpenSCAP to scan and remediate the system when a change that can affect the
# security is detected.

# SCAPmonitor requires the user to input the path of a specific file included
# in SCAP Security Guide (SSG): ssg-ubuntu2004-ds.xml
if [ $# != 1 ];
then
  echo "Usage: bash SCAPmonitor.sh filepath"
  echo "Where filepath refers to the ssg-ubuntu2004-ds.xml of SSG"
  exit
fi
FILEPATH="$1"

#Allows the termination of all concurrent processes with a single CTRL-C
trap "kill 0" SIGINT

echo "SCAPmonitor is starting..."

# The first five rules cannot be checked, as the changes can only occur at
# mount time:
# Rule: Ensure /home Located On Separate Partition
# Rule: Ensure /tmp Located On Separate Partition
# Rule: Ensure /var Located On Separate Partition
# Rule: Ensure /var/log Located On Separate Partition
# Rule: Ensure /var/log/audit Located On Separate Partition

# The other rules are wrapped in infinite while loops to ensure continuous
# monitoring. Using inotifywait blocks that particular loop until an event
# is detected.

# Rule: Ensure users own their home directories
while :
do
  inotifywait -q -e modify /etc/passwd |
  while read -r dir events filename; do
    echo "New event detected:"
    echo "Directory: $dir   events: $events   file: $filename"
    echo "Starting remediation..."
    oscap xccdf eval --remediate --report compliance-report-new.html \
    --profile standard $FILEPATH &>/dev/null
    echo "Remediation completed."
    echo ""
  done
done &

# The following rules check for the presence (or absence) of particular
# packages via polling. The while is repeated every SLEEPTIME seconds.
while :
do
  FLAG=0
  # SLEEPTIME specifies how frequently the following checks are performed
  SLEEPTIME=10

  # Rule: Ensure the audit Subsystem is Installed
  # Rule: Enable auditd Service
  ps -e | grep -w auditd >/dev/null
  if [ $? != 0 ];
  then
    FLAG=1
    echo "Service auditd not found"
  fi

  # Rule: Ensure rsyslog is Installed
  # Rule: Enable rsyslog Service
  ps -e | grep -w rsyslogd >/dev/null
  if [ $? != 0 ];
  then
    FLAG=1
    echo "Service rsyslog not found"
  fi

  # Rule: Disable Apport Service
  ps -e |grep apport >/dev/null
  if [ $? = 0 ];
  then
    FLAG=1
    echo "Service apport found"
  fi

  # Rule: Install the cron service
  # Rule: Enable cron Service
  ps -e | grep -w cron >/dev/null
  if [ $? != 0 ];
  then
    FLAG=1
    echo "Service cron not found"
  fi

  # Rule: Install the systemd_timesyncd Service
  # Rule: Enable systemd_timesyncd Service
  ps -e | grep -w systemd-timesyn >/dev/null
  if [ $? != 0 ];
  then
    FLAG=1
    echo "Service systemd_timesyncd not found"
  fi

  # Rule: Uninstall the inet-based telnet server
  dpkg -s inetutils-telnetd &>/dev/null
  if [ $? = 0 ];
  then
    FLAG=1
    echo "Package inetutils-telnetd found"
  fi

  # Rule: Uninstall the nis package
  dpkg -s nis &>/dev/null
  if [ $? = 0 ];
  then
    FLAG=1
    echo "Package nis found"
  fi

  # Rule: Uninstall the ntpdate package
  dpkg -s ntpdate &>/dev/null
  if [ $? = 0 ];
  then
    FLAG=1
    echo "Package ntpdate found"
  fi

  # Rule: Uninstall the ssl compliant telnet server
  dpkg -s telnetd-ssl &>/dev/null
  if [ $? = 0 ];
  then
    FLAG=1
    echo "Package telnetd-ssl found"
  fi

  # Rule: Uninstall the telnet server
  dpkg -s telnetd &>/dev/null
  if [ $? = 0 ];
  then
    FLAG=1
    echo "Package telnetd not found"
  fi

# Remediation is executed if at least one of the previous rules is NOT satisfied
  if [ $FLAG = 1 ];
  then
    echo "Starting remediation..."
    oscap xccdf eval --remediate --report compliance-report-new.html \
    --profile standard $FILEPATH &>/dev/null
    echo "Remediation completed"
    echo ""
  fi

  sleep $SLEEPTIME
done &


# Rule: Ensure Log Files Are Owned By Appropriate Group
# Rule: Ensure Log Files Are Owned By Appropriate User
# Rule: Ensure System Log Files Have Correct Permissions
while :
do
  inotifywait -q -e attrib /var/log |
  while read -r dir events filename; do
    echo "New event detected:"
    echo "Directory: $dir   events: $events   file: $filename"
    echo "Starting remediation..."
    oscap xccdf eval --remediate --report compliance-report-new.html \
    --profile standard $FILEPATH &>/dev/null
    echo "Remediation completed"
    echo ""
  done
done &

# Rule: Ensure Logrotate Runs Periodically
# Rule: Verify Group Who Owns group File
# Rule: Verify Group Who Owns gshadow File
# Rule: Verify Group Who Owns passwd File
# Rule: Verify Group Who Owns shadow File
# Rule: Verify User Who Owns group File
# Rule: Verify User Who Owns gshadow File
# Rule: Verify User Who Owns passwd File
# Rule: Verify User Who Owns shadow File
# Rule: Verify Permissions on group File
# Rule: Verify Permissions on gshadow File
# Rule: Verify Permissions on passwd File
# Rule: Verify Permissions on shadow File
while :
do
  inotifywait -q -e attrib /etc |
  while read -r dir events filename; do
    echo "New event detected:"
    echo "Directory: $dir   events: $events   file: $filename"
    echo "Starting remediation..."
    oscap xccdf eval --remediate --report compliance-report-new.html \
    --profile standard $FILEPATH &>/dev/null
    echo "Remediation completed"
    echo ""
  done
done &

# Rule: Verify that local System.map file (if exists) is readable only by root
while :
do
  inotifywait -q -e attrib /boot |
  while read -r dir events filename; do
    echo "New event detected:"
    echo "Directory: $dir   events: $events   file: $filename"
    echo "Starting remediation..."
    oscap xccdf eval --remediate --report compliance-report-new.html \
    --profile standard $FILEPATH &>/dev/null
    echo "Remediation completed"
    echo ""
  done
done &

# Rule: Enable Kernel Parameter to Enforce DAC on Hardlinks
# Rule: Enable Kernel Parameter to Enforce DAC on Symlinks
# Rule: Disable Core Dumps for SUID programs
# Rule: Enable Randomized Layout of Virtual Address Space
while :
do
  inotifywait -q -e modify /etc/sysctl.d |
  while read -r dir events filename; do
    echo "New event detected:"
    echo "Directory: $dir   events: $events   file: $filename"
    echo "Starting remediation..."
    oscap xccdf eval --remediate --report compliance-report-new.html \
    --profile standard $FILEPATH &>/dev/null
    echo "Remediation completed"
    echo ""
  done
done &

# Rule: Disable SSH Access via Empty Passwords
# Rule: Disable SSH Root Login
# Rule: Set SSH Idle Timeout Interval
# Rule: Set SSH Client Alive Count Max
while :
do
  inotifywait -q -e modify /etc/ssh |
  while read -r dir events filename; do
    echo "New event detected:"
    echo "Directory: $dir   events: $events   file: $filename"
    echo "Starting remediation..."
    oscap xccdf eval --remediate --report compliance-report-new.html \
    --profile standard $FILEPATH &>/dev/null
    echo "Remediation completed"
    echo ""
  done
done &

echo "SCAPmonitor is running."
echo ""

wait
