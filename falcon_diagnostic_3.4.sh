#!/bin/bash
# Linux Diagnostic Script version 3.4 - February 24nd, 2021
# Expects to be run as root
# Sensor diagnostic information
#

set -u

#
# This script creates a working directory under /var/tmp. We place this on
# /the /var/partition so that we may hafrdlink to logs under /var/logs.
# Before running, it checks to see if the directory already exists, and
# deletes it, to get rid of any data from previous runs to prevent confusion.
#

#
# The diagnostic information will be collected under ${diagnostic_dir}
# (/var/tmp/crowdstrike_diagnostics-<hostname>).
#
# The contents of ${diagnostic_dir} will be tar/zipped into
# /var/tmp/crowdstrike_diagnostics-<hostname>-<date>.tar.xz
#
var_tmp="/var/tmp"
diagnostic_subdir="crowdstrike_diagnostics"-`hostname`
diagnostic_dir=${var_tmp}/${diagnostic_subdir}
diagnostic_file=${diagnostic_subdir}-$(date +%F-%H-%M).tar.xz
extended_subdir="extended"
extended_dir="${diagnostic_dir}/${extended_subdir}"

if [ -d ${diagnostic_dir} ]; then
	rm -rf ${diagnostic_dir}
fi

mkdir -p ${diagnostic_dir}
mkdir -p ${extended_dir}

log_file="$diagnostic_dir/falcon_diagnostic.txt"
host_file="$diagnostic_dir/hardware_statistics.txt"
dmesg_file="$diagnostic_dir/dmesg_logfile.txt"
kernelmodule_file="$diagnostic_dir/kernelmodule_logfile.txt"
syslog_file="$diagnostic_dir/syslog_file.txt"
error_file="$diagnostic_dir/error_log.txt"
readme_file="${diagnostic_dir}/README"

function finish {
	#
	# Xz up the artifacts
	#
	echo "Creating archive of the results in ${var_tmp}/${diagnostic_file}"
	cd ${var_tmp}
	tar -cJf ${diagnostic_file} ${diagnostic_subdir}
#	rm -rf ${var_tmp}/${diagnostic_dir}
}

trap finish EXIT

#
# Root check
#
printf "Root Check\n" >> $log_file
if [ $(id -u) != 0 -o $(id -g) != 0 ]; then
	echo "Must be root to run this script! Exiting diagnostics." | tee -a $log_file
	exit 1
fi
printf "Root Check completed\n" >> $log_file

#
# Distribution checks
#
RHEL=0
UBUNTU=0
SUSE=0
AMZN=0

if [ -e /etc/redhat-release ]; then
	RHEL=1
	printf "RHEL system found\n" >> $log_file
	cat /etc/redhat-release >> $log_file
elif [ -e /etc/debian_version ]; then
	UBUNTU=1
	printf "Ubuntu system found\n" >> $log_file
	cat /etc/debian_version >> $log_file
elif [ -e /etc/SuSE-release ]; then
	SUSE=1
	printf "SUSE system found\n" >> $log_file
	cat /etc/SuSE-release >> $log_file
elif [ -e /etc/system-release ]; then
	AMZN=1
	printf "Amazon system found\n" >> $log_file
	cat /etc/system-release >> $log_file
else
	printf "Unknown distribution\n" >> $log_file
	if [ -e /etc/os-release ]; then
		cat /etc/os-release >> $log_file
	fi
fi

#
# Collect syslog
#
printf "Collecting syslog\n" | tee -a $log_file
if [ -f "/var/log/syslog" ]; then
	echo "`grep falcon /var/log/syslog | tail -n 10000`" >> $syslog_file
	echo "Syslog Data Found" | tee -a $log_file
	echo | tee -a $log_file
elif [ -f "/var/log/messages" ]; then
	echo "`grep falcon /var/log/messages | tail -n 10000`" >> $syslog_file
	echo "Syslog Data Found" | tee -a $log_file
	echo | tee -a $log_file
else
	echo "Syslog Data was NOT found!" | tee -a $log_file
	echo | tee -a $log_file
fi

#
# Collect dmesg
#
printf "Collecting dmesg\n" | tee -a $log_file
echo "`dmesg`" >> $dmesg_file
printf "Gathered dmesg\n"
echo | tee -a $log_file

#
# Check CID
#
echo "----------------CID and AID----------------" >> $log_file
printf "Checking if Customer ID (aka CID) has been set\n" | tee -a $log_file
cid=`/opt/CrowdStrike/falconctl -g --cid | grep -o -P '([a-zA-Z0-9]*)' | tail -n 1`
if [ -z $cid ]; then
	echo "Customer ID is NOT set!" | tee -a $log_file $error_file
	echo "To set the CID run this command: /opt/CrowdStrike/falconctl -s --cid=[Customer ID and Checksum]" | tee -a $log_file $error_file
	echo "Example: /opt/CrowdStrike/falconctl -s --cid=1234567890123456789-12" | tee -a $log_file $error_file
	echo | tee -a $log_file
	exit 1
else
	echo "Customer ID is $cid" | tee -a $log_file
	echo | tee -a $log_file
fi

#
# Check AID
#
printf "Checking if the sensor's agent ID (aka AID) has been generated\n" | tee -a $log_file
aid=`/opt/CrowdStrike/falconctl -g --aid | grep -o -P '([a-zA-Z0-9]*)' | tail -n 1`
if [ -z $aid ] || [ $aid == "set" ]; then
	echo "Agent ID has NOT been generated" | tee -a $log_file
	echo | tee -a $log_file
else
	echo "Agent ID is $aid" | tee -a $log_file
	echo | tee -a $log_file
fi

#
# Check if sensor is running
#
echo "----------------Sensor Status----------------" >> $log_file
printf "Checking if falcon-sensor is currently running\n" | tee -a $log_file
running=`ps -e | grep -e falcon-sensor`
if [[ ! -z $running ]]; then
	echo "falcon-sensor is running" | tee -a $log_file
	echo "$running" >> $log_file
	echo | tee -a $log_file
else
	echo "ERROR falon-sensor is NOT running!" | tee -a $log_file $error_file
	echo | tee -a $log_file
fi

#
# If sensor isn't running, collect the service status
# keeping in mind of systemd vs init requirements
#
if [[ -z $running ]]; then
	sysv_init=0
	systemd=0
	if [ -x "$(command -v systemctl)" ]; then
		systemd=1
	else
		sysv_init=1
	fi

	if [ $systemd == 1 ]; then
		systemctl show falcon-sensor >> $log_file
	elif [ $sysv_init == 1]; then
		if [ -f /etc/init.d/falcon-sensor ]; then
			cat /etc/init.d/falcon-sensor >> $log_file
		else
			echo "Unknown location for init script" >> $log_file
		fi
	fi
fi

#
# Check the installed sensor version
#
echo "------------Installed Sensor Version------------" >> $log_file
echo "`/opt/CrowdStrike/falconctl -g --version`" | tee -a $log_file
printf "Gathered version of the current running sensor\n"
echo | tee -a $log_file


#
# Check the installed RPM package info from the RPM/DPKG database
#
echo "----------------RPM----------------" >> $log_file
printf "Gathering installed RPM Package Info\n" | tee -a $log_file
if [ $UBUNTU == 1 ]; then
	echo "`dpkg -g falcon-sensor`" >> $log_file
else
	echo "`rpm -qi falcon-sensor`" >> $log_file
fi
printf "Gathered installed RPM Package Info\n"
echo | tee -a $log_file

echo "$(readlink -f /proc/`pgrep falcon-sensor`/exe)" | tee -a $log_file

#
# Check falcon-sensor status
#
printf "Gathering falcon-sensor status\n"
echo "`service falcon-sensor status 2>&1`" >> $log_file
printf "Gathered falcon-sensor status\n"
echo | tee -a $log_file

#
# Verify sensor files on disk
#
echo "----------------Sensor Files----------------" >> $log_file
printf "Checking if sensor files are on disk\n" | tee -a $log_file
if [ -d "/opt/CrowdStrike" ]; then
	if [ -x "$(command -v ls)" ]; then
		ls -al /opt/CrowdStrike /opt/CrowdStrike/falcon-sensor >> $log_file
		echo "Sensor files were found" | tee -a $log_file
		echo | tee -a $log_file
	fi
else
	echo "Sensor files were NOT found on disk!" | tee -a $log_file $error_file
	echo | tee -a $log_file
fi

#
# Check kernel modules to verify the Falcon sensor's kernel modules are running
#
echo "----------------Kernel Module Status----------------" >> $log_file
printf "Checking if kernel modules are running\n" | tee -a $log_file
if [ -x "$(command -v lsmod)" ]; then
	lsmodules=`lsmod | grep falcon`
	if [[ ! -z $lsmodules ]]; then
		echo "$lsmodules" | tee -a $log_file
		echo "Kernel modules are running" | tee -a $log_file
		echo | tee -a $log_file
	else
		echo "Kernel modules are NOT running" | tee -a $log_file $error_file
		echo | tee -a $log_file
	fi
fi

#
# Checking if running kernel is supported
#
echo "----------------Kernel Version Supported----------------" >> $log_file
printf "Checking if currently running kernel is supported\n" | tee -a $log_file
supported=0
if [ -f "/opt/CrowdStrike/KernelModuleArchive" ]; then
	if [ -x "$(command -v strings)" ]; then
		supported_kernels=`strings /opt/CrowdStrike/KernelModuleArchive | grep '^[2-4]\..*'`
		echo "$supported_kernels" >> $kernelmodule_file
		if [ -x "$(command -v uname)" ]; then
			curr_kernel=`uname -r`
			echo "Currently running kernel is $curr_kernel" | tee -a $log_file
			for kernel in $supported_kernels; do
				if [ "$curr_kernel" == "$kernel" ]; then
					supported=1
					break
				fi
			done
		fi
	fi
fi
if [ $supported == 1 ]; then
	echo "$curr_kernel is supported" | tee -a $log_file
	echo | tee -a $log_file
else
	echo "$curr_kernel is NOT supported" | tee -a $log_file $error_file
fi
printf "Finished checking kernel support\n" | tee -a $log_file
echo | tee -a $log_file


#
# sha256 all files in CrowdStrike dir
#
echo "----------------SHA 256 Hashes----------------" >> $log_file
echo "Gathering SHA256 hashes"
if [ -x "$(command -v sha256sum)" -a -d "/opt/CrowdStrike" ]; then
	for file in `ls /opt/CrowdStrike`; do
		echo "`sha256sum /opt/CrowdStrike/$file 2>&1`" >> $log_file
	done
fi
echo | tee -a $log_file

#
# Check status of SELinux (RHEL/CentOS/SLES)
#
echo "----------------SELinux Status----------------" >> $log_file
echo "Gathering SELinux Status"
if [ ! -x "$(command -v sestatus)" ]; then
    echo "sestatus not installed." >> $log_file
else
    echo "`sestatus`" >> $log_file
    echo | tee -a $log_file
fi

#
# Check status of App Armor (Ubuntu)
#
echo "----------------App Armor Status----------------" >> $log_file
echo "Gathering App Armor Status"
if [ ! -x "$(command -v aa-status)" ]; then
    echo "aa-status not installed." >> $log_file
else
    echo "`aa-status`" >> $log_file
    echo | tee -a $log_file
fi

printf "Running Network Checks\n"

#
# Verify sensor is connected to the cloud
#
echo "----------------Connectivity Info----------------" >> $log_file
printf "Checking if sensor is connected to CrowdStrike Cloud\n" | tee -a $log_file
if [ -x "$(command -v netstat)" ]; then
	cloud_check=`netstat -tapn | grep falcon-sensor`
	if [[ -z $cloud_check ]]; then
    echo "falcon-sensor is Not connected to CrowdStrike Cloud" | tee -a $log_file $error_file
  	echo | tee -a $log_file
	fi
else
  echo "netstat command does not exist" | tee -a $log_file
fi

#
# Verify sensor proxy status
#
echo "----------------Proxy Status----------------" >> $log_file
printf "Checking proxy status\n" | tee -a $log_file
proxy_check=`/opt/CrowdStrike/falconctl -g --apd | grep -o -P '([a-zA-Z0-9]*)' | tail -n 1`
proxy=`/opt/CrowdStrike/falconctl -g --apd --aph --app`
if [ -z $proxy_check ] || [ $proxy_check == "set" ]; then
	echo "Proxy settings are NOT set" | tee -a $log_file
	echo | tee -a $log_file
else
	echo "$proxy" | tee -a $log_file
	echo | tee -a $log_file
fi

#
# Check Installed OpenSSL versions and attempt connection
#
if [ ! -x "$(command -v openssl)" ]; then
  echo "OpenSSL NOT installed. It is required for connectivity." >> $log_file $error_log
  else
    echo "----------------Installed SSL Versions----------------" >> $log_file
    printf "Gathering OpenSSL version information\n"
    echo "`rpm -qa |grep -i openssl`" >> $log_file
    echo | tee -a $log_file
    printf "Attempting OpenSSL connection to ts01-b.cloudsink.net:443\n" >> $log_file
    echo "Please Note: This check will fail if a proxy is enabled." >> $log_file
    echo "`openssl s_client -connect ts01-b.cloudsink.net:443`" 2>&1 >> $log_file
    echo | tee -a $log_file
fi

#
# Check IP tables for any custom routing rules that may interfere
#
echo "----------------IP Tables----------------" >> $log_file
printf "Gathering IP Tables rules\n"
echo "`iptables -L -n`" >> $log_file
echo | tee -a $log_file

printf "Checking System Hardware\n"

#
# Check disk space
#
echo "----------------Disk Space Information----------------" >> $host_file
printf "Gathering disk space information\n"
echo "`df -h`" >> $host_file
echo | tee -a $host_file

#
# Check CPU and IO info
#
if [ ! -x "$(command -v iostat)" ]; then
  echo "iostat not installed." >> $host_file
  else
    echo "----------------CPU and I/O Info----------------" >> $host_file
    printf "Gathering CPU and I/O information\n"
    echo "`iostat`" >> $host_file
    echo | tee -a $host_file
fi

#
# Check Memory Information
#
if [ ! -x "$(command -v vmstat)" ]; then
  echo "vmstat not installed." >> $host_file
  else
    echo "----------------Memory Info----------------" >> $host_file
    printf "Gathering Memory information\n"
    echo "`vmstat`" >> $host_file
    echo | tee -a $host_file
fi

#
# Check Process Information
#
echo "----------------Process Info----------------" >> $host_file
printf "Collecting processor information\n" | tee -a $host_file
if [ -x "$(command -v lscpu)" ]; then
    echo "`lscpu`" >> $host_file
    echo | tee -a $host_file
fi

#
#Check to see how much memory the sensor is using per CPU Thread
#
echo "--------------Per-Thread Memory Usage--------------" >> $log_file
if [ -x "$(command -v pgrep)" ]; then
  if [[ ! -z $running ]]; then
    pid=`pgrep falcon-sensor`
    if [[ ! -z $pid ]]; then
      psid=`ps -p $pid -L -o pid,tid,psr,pcpu,comm=`
      echo "$psid" >> $log_file
      echo | tee -a $log_file
      echo "Collected per-thread usage" | tee -a $log_file
        echo | tee -a $log_file
     fi
  else
    echo "Per-thread usage cannot be collected because falon-sensor is not running!" | tee -a $log_file
    echo | tee -a $log_file
  fi
else
  echo "pgrep command does not exist!" | tee -a $log_file
  echo | tee -a $log_file
fi

#
# Check queue depths
#
echo "----------------Queue Info----------------" >> $log_file
printf "Gathering queue depths\n"
for f in /proc/falcon_lsm_serviceable/queue_depth/*; do
    echo "$(basename $f)" >> $log_file
    cat "$f" >> $log_file
done
echo | tee -a $log_file

#
# Check diskspace
#
echo "----------------Disk Space Information----------------" >> $host_file
printf "Gathering disk space information\n"
echo "`df -h`" >> $host_file
echo | tee -a $host_file

#
# Check CPU and IO info
#
if [ ! -x "$(command -v iostat)" ]; then
  echo "iostat not installed." >> $host_file
  else
    echo "----------------CPU and I/O Info----------------" >> $host_file
    printf "Gathering CPU and I/O information\n"
    echo "`iostat`" >> $host_file
    echo | tee -a $host_file
fi

#
# Check Memory Information
#
if [ ! -x "$(command -v vmstat)" ]; then
  echo "vmstat not installed." >> $host_file
  else
    echo "----------------Memory Info----------------" >> $host_file
    printf "Gathering Memory information\n"
    echo "`vmstat`" >> $host_file
    echo | tee -a $host_file
fi

printf "Gathering Top information\n" | tee -a $host_file
echo "`top -b -n 1`" >> $host_file
echo | tee -a $host_file

#
# Check fork rate
#
if [ ! -x "$(command -v vmstat)" ]; then
  echo "vmstat not installed." >> $host_file
  else
    echo "----------------Fork Rate----------------" >> $host_file
    printf "Gathering system fork rate\n"
    t=5
    start=$(vmstat -f | awk '{print $1}')
    sleep $t
    end=$(vmstat -f | awk '{print $1}')
    rate=$(((end - start) / t))
    echo "$rate forks per second" >> $host_file
    echo | tee -a $host_file
fi

#
# If error_log exists, tail it's contents to terminal
#
if [[ -e $diagnostic_dir/error_log.txt ]]; then
  echo "------------------------------------------"
  echo "`tail -n 100 $diagnostic_dir/error_log.txt`"
  echo "------------------------------------------"
fi

printf "Gathering extended configuration and state information\n" | tee -a $log_file

#
# Below, we create a 2 dimensional array, containg commands to execute
# (to gather diagnostice information) and the targe filenames to write
# the output of the command.
#
# Some commands may either copy or link an existing file, in which
# case the target filename should be /dev/null.
#
# On some customer systems, these commands may fail. Either because the
# OS doesn't # support the command or the required package may not be
# installed. In this case, the command will quietly fail and the target
# file will not be generated.
#
cd ${extended_dir}

echo "Below is summary of the files created." >> $readme_file
echo "In addition, additonal configuration and log files are also included." >> $readme_file
echo >> $readme_file
echo "falcon_diagnostic.txt: a variety of server configuration and state information." >> $readme_file
echo "hardware_statistics.txt: server CPU, memory, process and disk information." >> $readme_file
echo "dmesg_logfile.txt: contents of /var/log/dmesg, the kernel ring buffer." >> $readme_file
echo "kernelmodule_logfile.txt: the kernel configuration log file." >> $readme_file
echo "syslog_file.txt: the last 10000 lines of /var/log/messages or /var/log/syslog." >> $readme_file
echo "error_log.txt: the Falcon sensor error log file." >> $readme_file
echo >> $readme_file
echo "With release of version 3.3 of falcon_diagnostics.sh:" >> $readme_file

 command_array=('cat /proc/`pidof falcon-sensor`/maps'                                                        fs-proc-maps.txt)
command_array+=('cat /proc/`pidof falcon-sensor`/numa_maps'                                                   fs-proc-numamaps.txt)
command_array+=('cat /proc/`pidof falcon-sensor`/smaps'                                                       fs-proc-smaps.txt)
command_array+=('cat /proc/`pidof falcon-sensor`/smaps_rollup'                                                fs-proc-smaps_rollup.txt)
command_array+=('cat /proc/`pidof falcon-sensor`/stack'                                                       fs-proc-stack.txt)
command_array+=('cat /proc/`pidof falcon-sensor`/status'                                                      fs-proc-status.txt)
command_array+=('cat /proc/buddyinfo'                                                                         fs-proc-buddyinfo.txt)
command_array+=('cat /proc/cmdline .'                                                                          proc-cmdline.txt)
command_array+=('cat /proc/meminfo'                                                                           proc-meminfo.txt)
command_array+=('cat /proc/pagetypeinfo'                                                                      proc-pagetypeinfo.txt)
command_array+=('cat /proc/slabinfo'                                                                          proc-slabinfo.txt)
command_array+=('cat /proc/swaps'                                                                             proc-swaps.txt)
command_array+=('cat /proc/sys/kernel/tainted'                                                                proc-kernel-tainted.txt)
command_array+=('cat /proc/vmallocinfo'                                                                       proc-vmallocinfo.txt)
command_array+=('cat /proc/vmstat'                                                                            proc-vmstat.txt)
command_array+=('cat /proc/zoneinfo'                                                                          proc-zoneinfo.txt)
command_array+=('cp /proc/config.z .'                                                                         proc-config.z)
command_array+=('df -aH'                                                                                      df-aH.txt)
command_array+=('dmidecode -t bios'                                                                           bios.txt)
command_array+=('fdisk -l'                                                                                    fdisk-l.txt)
command_array+=('fips-mode-setup --check'                                                                     fips-mode-setup.txt)
command_array+=('find /proc/sys/kernel /proc/sys/vm -type f -print -exec cat {} \;'                           proc-sys.txt)
command_array+=('findmnt -a'                                                                                  find-mnt.txt)
command_array+=('free -h'                                                                                     free.txt)
command_array+=('hostinfo'                                                                                    hostinfo.txt)
command_array+=('ifconfig'                                                                                    ifconfig.txt)
command_array+=('ip link show'                                                                                ip-link-show.txt)
command_array+=('lsblk'                                                                                       lsblk.txt)
command_array+=('lscpu'                                                                                       lscpu.txt)
command_array+=('lsdev'                                                                                       lsdev.txt)
command_array+=('lshw'                                                                                        lshw.txt)
command_array+=('lsipc'                                                                                       lsipc.txt)
command_array+=('lsinitrd'                                                                                    lsinitrd.txt)
command_array+=('lslocks'                                                                                     lslocks.txt)
command_array+=('lsmem'                                                                                       lsmem.txt)
command_array+=('lsmod'                                                                                       lsmod.txt)
command_array+=('lsof'                                                                                        lsof.txt)
command_array+=('lsof -p `pidof falcon-sensor`'                                                               fs-lsof.txt)
command_array+=('lspci'                                                                                       lspci.txt)
command_array+=('lsscsi'                                                                                      lsscsi.txt)
command_array+=('ls -l /opt/CrowdStrike'                                                                      ls-opt-crowdstrike.txt)
command_array+=('mount -l'                                                                                    mount.txt)
command_array+=('netstat -i'                                                                                  netstat-i.txt)
command_array+=('netstat -r'                                                                                  netstat-r.txt)
command_array+=('netstat -s'                                                                                  netstat-s.txt)
command_array+=('nstat'                                                                                       nstat.txt)
command_array+=('pmap -x `pidof falcon-sensor`'                                                               fs-pmap-x.txt)
command_array+=('pmap -xXX `pidof falcon-sensor`'                                                             fs-pmap-xXX.txt)
command_array+=('prtstat `pidof falcon-sensor`'                                                               fs-prtstat.txt)
command_array+=('ps agxfww -eo user,pid,ppid,%cpu,cputime,%mem,cls,lwp,nlwp,pri,trs,vsz,rss,sz,size,cmd'      ps-agxz.txt)
command_array+=('pstack `pidof falcon-sensor`'                                                                fs-pstack.txt)
command_array+=('service --status-all'                                                                        service-status-all.txt)
command_array+=('slabtop -o'                                                                                  slabtop.txt)
command_array+=('sysctl -A'                                                                                   sysctl-A.txt)
command_array+=('systemctl -al'                                                                               systemctl-aL.txt)
command_array+=('systemctl -ln 500 status falcon-sensor'                                                      systemctl-ln-falcon-sensor.txt)
command_array+=('systemctl status kdump.service'                                                              systemctl-kdump.service.txt)
command_array+=('systemd-detect-virt'                                                                         systemd-detect-virt.txt)
command_array+=('systemd-cgtop -b -n 1'                                                                       systemd-cgtop.txt)
command_array+=('top -bH -n1'                                                                                 top.txt)
command_array+=('ulimit -a'                                                                                   ulimit-a.txt)
command_array+=('uname -a'                                                                                    uname-a.txt)
command_array+=('uptime'                                                                                      uptime.txt)
command_array+=('vmstat -m'                                                                                   vmstat-m.txt)
command_array+=('vmstat -s'                                                                                   vmstat-s.txt)
command_array+=('vmstat -w'                                                                                   vmstat-w.txt)
command_array+=('/opt/CrowdStrike/falconctl -g --cid'                                                         falconctl.txt)
command_array+=('/opt/CrowdStrike/falconctl -g --aid'                                                         falconctl.txt)
command_array+=('/opt/CrowdStrike/falconctl -g --rfm-state'                                                   falconctl.txt)
command_array+=('/opt/CrowdStrike/falconctl -g --rfm-reason'                                                  falconctl.txt)
command_array+=('/opt/CrowdStrike/falconctl -g --trace'                                                       falconctl.txt)
command_array+=('/opt/CrowdStrike/falconctl -g --feature'                                                     falconctl.txt)
command_array+=('/opt/CrowdStrike/falconctl -g --tags'                                                        falconctl.txt)
#
# The following either links (if the file is on /var, to save space) or copies
# the file(s) to the collection directory.
#
command_array+=('cp /etc/fstab .'                                                                             /dev/null)
command_array+=('cp /etc/os-release .'                                                                        /dev/null)
command_array+=('cp /etc/redhat-release .'                                                                    /dev/null)
command_array+=('cp /etc/debian_version .'                                                                    /dev/null)
command_array+=('cp /etc/security/limits.conf .'                                                              /dev/null)
command_array+=('cp /etc/sysctl.conf .'                                                                       /dev/null)
command_array+=('cp /etc/system-release .'                                                                    /dev/null)
command_array+=('cp /etc/systemd/system/falcon-sensor.service.d/override.conf .'                              /dev/null)
command_array+=('cp /opt/CrowdStrike/Registry.bin .'                                                          /dev/null)
command_array+=('cp /etc/systemd/system/falcon-sensor.service.d/override.conf .'                              /dev/null)
command_array+=('cp /usr/lib/systemd/system/falcon-sensor.service .'                                          /dev/null)
command_array+=('find /var/log -name 'dmesg*' -exec ln {} \;'                                                 /dev/null)
command_array+=('find /var/log -name 'falcon-sensor.log*' -exec ln {} \;'                                     /dev/null)
command_array+=('find /var/log -name 'message*' -exec ln {} \;'                                               /dev/null)
command_array+=('find /var/log -name 'syslog*' -exec ln {} \;'                                                /dev/null)
command_array+=('ln /var/log/boot.log'                                                                        /dev/null)
command_array+=('ln /var/log/falconctl.log'                                                                   /dev/null)
command_array+=('supportconfig -Rl ${diagnostic_dir}'                                                          /dev/null)

command_array_length=`expr ${#command_array[@]} / 2`

#
# Loop through command_array, executing each command and redirecting the output
# to the specified file. If the command fails, remove the target file (unless it
# is /dev/null.
#
# In addition, generate a README listing the files generated and the command
# used to create it.
#
i=0
while [ $i -lt ${command_array_length} ];
do
eval ${command_array[2 * $i]} >> ${command_array[(2 * $i) + 1]} 2>&1

if [ $? -eq 0 ]; then
	if [ "${command_array[(2 * $i) + 1]}" != "/dev/null" ]; then
		echo "Created ${command_array[(2 * $i) + 1]}" | tee -a $log_file
		echo "${extended_subdir}/${command_array[(2 * $i) + 1]}: contents of \"${command_array[2 * $i]}\"" >> $readme_file
	fi
else
	echo "\"${command_array[2 * $i]}\" not supported" | tee -a $log_file
	if [ "${command_array[(2 * $i) + 1]}" != "/dev/null" ]; then
		rm ${command_array[(2 * $i) + 1]}
	fi
fi

i=`expr $i + 1`
done

printf "Completed Falcon diagnostic\n" | tee -a $log_file
