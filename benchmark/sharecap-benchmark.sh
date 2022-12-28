#!/bin/bash

replayer_box=development-pcap-replayer-001

mkdir -p res
rm -f results

loops=3

options=4
option[0]="suricata_pcap"
option[1]="suricata_afpacket"
option[2]="suricata_sharecap_file"
option[3]="suricata_sharecap_interface"

option_s[0]="--pcap=eth0"
option_s[1]="-i eth0"
option_s[2]="-r /tmp/sharecap/sharecap-0-0"
option_s[3]="--pcap=sharecap-0-0"

for pcap in pcap_small_rewr.pcap office_dump_rewr.pcap pcap_2gb_rewr.pcap; do
	echo "Starting native libpcap capture test"
	echo "Starting capture_test"
	sudo /usr/bin/time -v capture_test eth0 &> res/capture_test_${pcap}_output &
	sleep 2
	echo "Playing $pcap from $replayer_box"
	ssh $replayer_box "sudo tcpreplay -i eth0 -t -l ${loops} /pcaps/${pcap} 2> /dev/null"
	echo "Played $pcap - stopping capture_test"
	pid=`ps aux | grep capture_test | grep -v time | grep -v grep | grep -v sudo | awk '{print $2}'`
	mem_capture=`sudo pmap $pid | grep total | awk '{split($2,a,"K"); print a[1]/1024}'`
	sys_mem_capture=`free | grep Mem | awk '{print $3/1024}'`
	sudo kill -TERM $pid
	sleep 5

	bytes_capture=`grep "Processed" res/capture_test_${pcap}_output | awk '{print $4}'`
	pkts_capture=`grep "Processed" res/capture_test_${pcap}_output | awk '{print $2}'`
	pktsize_capture=`echo "$bytes_capture / $pkts_capture" | bc -l`
	cpu_capture=`grep "Percent of CPU this job got" res/capture_test_${pcap}_output | awk '{print $7}'`
	mrss_capture=`grep "Maximum resident set size" res/capture_test_${pcap}_output | awk '{print $6/1024}'`
	utime_capture=`grep "User time" res/capture_test_${pcap}_output | awk '{print $4}'`
	stime_capture=`grep "System time" res/capture_test_${pcap}_output | awk '{print $4}'`
	xput_capture=`echo "$bytes_capture * 8 / ( $utime_capture + $stime_capture ) / 1000000" | bc -l`
	echo -e "capture_test\t${pcap}\tCPU: ${cpu_capture}\tSystem mem used: ${sys_mem_capture} MB\tMem: ${mem_capture} MB\tMRSS: ${mrss_capture} MB\tBytes: ${bytes_capture}\tPackets: ${pkts_capture}\tAverage packet size: ${pktsize_capture} bytes\tProcessing throughput: ${xput_capture} Mbps" >> results

	echo "Starting native ShareCap capture test"
	echo "Starting master"
	sudo /usr/bin/time -v ../test_sharecap/master -i eth0 -c 1 &> res/master_sharecap_native_${pcap}_output &
	sleep 2
	echo "Starting client"
	sudo /usr/bin/time -v ../test_sharecap/client -c 0 &> res/client_sharecap_native_${pcap}_output &
	sleep 2
	echo "Playing $pcap from $replayer_box"
	ssh $replayer_box "sudo tcpreplay -i eth0 -t -l ${loops} /pcaps/${pcap} 2> /dev/null"
	echo "Played $pcap - stopping master and client"
	sys_mem_sharecap_native=`free | grep Mem | awk '{print $3/1024}'`
	pid_master=`ps aux | grep "master -i" | grep -v time | grep -v grep | grep -v sudo | awk '{print $2}'`
	pid_client=`ps aux | grep "client -c 0" | grep -v time | grep -v grep | grep -v sudo | awk '{print $2}'`
	mem_sharecap_native_master=`sudo pmap $pid_master | grep total | awk '{split($2,a,"K"); print a[1]/1024}'`
	mem_sharecap_native=`sudo pmap $pid_client | grep total | awk '{split($2,a,"K"); print a[1]/1024}'`
	sudo kill -TERM $pid_master
	sleep 5
	sudo kill -TERM $pid_client
	sleep 5

	bytes_sharecap_native=`grep "processed" res/client_sharecap_native_${pcap}_output | grep pkts | tail -1 | awk '{print $6}'`
	pkts_sharecap_native=`grep "processed" res/client_sharecap_native_${pcap}_output | grep pkts | tail -1 | awk '{print $4}'`
	pktsize_sharecap_native=`echo "$bytes_sharecap_native / $pkts_sharecap_native" | bc -l`
	cpu_sharecap_native=`grep "Percent of CPU this job got" res/client_sharecap_native_${pcap}_output | awk '{print $7}'`
	mrss_sharecap_native=`grep "Maximum resident set size" res/client_sharecap_native_${pcap}_output | awk '{print $6/1024}'`
	utime_sharecap_native=`grep "User time" res/client_sharecap_native_${pcap}_output | awk '{print $4}'`
	stime_sharecap_native=`grep "System time" res/client_sharecap_native_${pcap}_output | awk '{print $4}'`
	xput_sharecap_native=`echo "$bytes_sharecap_native * 8 / ( $utime_sharecap_native + $stime_sharecap_native ) / 1000000" | bc -l`
	cpu_sharecap_native_master=`grep "Percent of CPU this job got" res/master_sharecap_native_${pcap}_output | awk '{print $7}'`
	mrss_sharecap_native_master=`grep "Maximum resident set size" res/master_sharecap_native_${pcap}_output | awk '{print $6/1024}'`
	utime_sharecap_native_master=`grep "User time" res/master_sharecap_native_${pcap}_output | awk '{print $4}'`
	stime_sharecap_native_master=`grep "System time" res/master_sharecap_native_${pcap}_output | awk '{print $4}'`
	xput_sharecap_native_master=`echo "$bytes_sharecap_native * 8 / ( $utime_sharecap_native_master + $stime_sharecap_native_master ) / 1000000" | bc -l`
	echo -e "sharecap_native_test\t${pcap}\tCPU: ${cpu_sharecap_native}\tSystem mem used: ${sys_mem_capture} MB\tMem: ${mem_sharecap_native} MB\tMRSS: ${mrss_sharecap_native} MB\tBytes: ${bytes_sharecap_native}\tPackets: ${pkts_sharecap_native}\tAverage packet size: ${pktsize_sharecap_native} bytes\tProcessing throughput: ${xput_sharecap_native} Mbps\tMaster CPU: ${cpu_sharecap_native_master}\tMaster mem usage: ${mem_sharecap_native_master} MB\tMaster MRSS: ${mrss_sharecap_native_master} MB\tMaster processing throughput: ${xput_sharecap_native_master} Mbps" >> results

	echo "Starting ShareCap libpcap wrapper capture test (virtual file)"
	echo "Starting master"
	sudo /usr/bin/time -v ../test_sharecap/master -i eth0 -c 1 &> res/master_sharecap_wrapper_file_${pcap}_output &
	sleep 2
	echo "Starting capture_test"
	sudo LD_PRELOAD=../libpcap/libpcap.so /usr/bin/time -v capture_test /tmp/sharecap/sharecap-0-0 &> res/client_sharecap_wrapper_file_${pcap}_output &
	sleep 2
	echo "Playing $pcap from $replayer_box"
	ssh $replayer_box "sudo tcpreplay -i eth0 -t -l ${loops} /pcaps/${pcap} 2> /dev/null"
	echo "Played $pcap - stopping capture_test and master"
	sys_mem_sharecap_wrapper_file=`free | grep Mem | awk '{print $3/1024}'`
	pid_master=`ps aux | grep "master -i" | grep -v time | grep -v grep | grep -v sudo | awk '{print $2}'`
	pid_client=`ps aux | grep capture_test | grep -v time | grep -v grep | grep -v sudo | awk '{print $2}'`
	mem_sharecap_wrapper_file_master=`sudo pmap $pid_master | grep total | awk '{split($2,a,"K"); print a[1]/1024}'`
	mem_sharecap_wrapper_file=`sudo pmap $pid_client | grep total | awk '{split($2,a,"K"); print a[1]/1024}'`
	sudo kill -TERM $pid_master
	sleep 5
	sudo kill -TERM $pid_client
	sleep 5

	bytes_sharecap_wrapper_file=`grep "Processed" res/client_sharecap_wrapper_file_${pcap}_output | awk '{print $4}'`
	pkts_sharecap_wrapper_file=`grep "Processed" res/client_sharecap_wrapper_file_${pcap}_output | awk '{print $2}'`
	pktsize_sharecap_wrapper_file=`echo "$bytes_sharecap_wrapper_file / $pkts_sharecap_wrapper_file" | bc -l`
	cpu_sharecap_wrapper_file=`grep "Percent of CPU this job got" res/client_sharecap_wrapper_file_${pcap}_output | awk '{print $7}'`
	mrss_sharecap_wrapper_file=`grep "Maximum resident set size" res/client_sharecap_wrapper_file_${pcap}_output | awk '{print $6/1024}'`
	utime_sharecap_wrapper_file=`grep "User time" res/client_sharecap_wrapper_file_${pcap}_output | awk '{print $4}'`
	stime_sharecap_wrapper_file=`grep "System time" res/client_sharecap_wrapper_file_${pcap}_output | awk '{print $4}'`
	xput_sharecap_wrapper_file=`echo "$bytes_sharecap_wrapper_file * 8 / ( $utime_sharecap_wrapper_file + $stime_sharecap_wrapper_file ) / 1000000" | bc -l`
	cpu_sharecap_wrapper_file_master=`grep "Percent of CPU this job got" res/master_sharecap_wrapper_file_${pcap}_output | awk '{print $7}'`
	mrss_sharecap_wrapper_file_master=`grep "Maximum resident set size" res/master_sharecap_wrapper_file_${pcap}_output | awk '{print $6/1024}'`
	utime_sharecap_wrapper_file_master=`grep "User time" res/master_sharecap_wrapper_file_${pcap}_output | awk '{print $4}'`
	stime_sharecap_wrapper_file_master=`grep "System time" res/master_sharecap_wrapper_file_${pcap}_output | awk '{print $4}'`
	xput_sharecap_wrapper_file_master=`echo "$bytes_sharecap_wrapper_file * 8 / ( $utime_sharecap_wrapper_file_master + $stime_sharecap_wrapper_file_master ) / 1000000" | bc -l`
	echo -e "sharecap_wrapper_file_test\t${pcap}\tCPU: ${cpu_sharecap_wrapper_file}\tSystem mem used: ${sys_mem_sharecap_wrapper_file} MB\tMem: ${mem_sharecap_wrapper_file} MB\tMRSS: ${mrss_sharecap_wrapper_file} MB\tBytes: ${bytes_sharecap_wrapper_file}\tPackets: ${pkts_sharecap_wrapper_file}\tAverage packet size: ${pktsize_sharecap_wrapper_file} bytes\tProcessing throughput: ${xput_sharecap_wrapper_file} Mbps\tMaster CPU: ${cpu_sharecap_wrapper_file_master}\tMaster mem usage: ${mem_sharecap_wrapper_file_master} MB\tMaster MRSS: ${mrss_sharecap_wrapper_file_master} MB\tMaster processing throughput: ${xput_sharecap_wrapper_file_master} Mbps" >> results

	echo "Starting ShareCap libpcap wrapper capture test (virtual interface)"
	echo "Starting master"
	sudo /usr/bin/time -v ../test_sharecap/master -i eth0 -c 1 &> res/master_sharecap_wrapper_interface_${pcap}_output &
	sleep 2
	echo "Starting capture_test"
	sudo LD_PRELOAD=../libpcap/libpcap.so /usr/bin/time -v capture_test sharecap-0-0 &> res/client_sharecap_wrapper_interface_${pcap}_output &
	sleep 2
	echo "Playing $pcap from $replayer_box"
	ssh $replayer_box "sudo tcpreplay -i eth0 -t -l ${loops} /pcaps/${pcap} 2> /dev/null"
	echo "Played $pcap - stopping capture_test and master"
	sys_mem_sharecap_wrapper_interface=`free | grep Mem | awk '{print $3/1024}'`
	pid_master=`ps aux | grep "master -i" | grep -v time | grep -v grep | grep -v sudo | awk '{print $2}'`
	pid_client=`ps aux | grep capture_test | grep -v time | grep -v grep | grep -v sudo | awk '{print $2}'`
	mem_sharecap_wrapper_interface_master=`sudo pmap $pid_master | grep total | awk '{split($2,a,"K"); print a[1]/1024}'`
	mem_sharecap_wrapper_interface=`sudo pmap $pid_client | grep total | awk '{split($2,a,"K"); print a[1]/1024}'`
	sudo kill -TERM $pid_master
	sleep 5
	sudo kill -TERM $pid_client
	sleep 5

	bytes_sharecap_wrapper_interface=`grep "Processed" res/client_sharecap_wrapper_interface_${pcap}_output | awk '{print $4}'`
	pkts_sharecap_wrapper_interface=`grep "Processed" res/client_sharecap_wrapper_interface_${pcap}_output | awk '{print $2}'`
	pktsize_sharecap_wrapper_interface=`echo "$bytes_sharecap_wrapper_interface / $pkts_sharecap_wrapper_interface" | bc -l`
	cpu_sharecap_wrapper_interface=`grep "Percent of CPU this job got" res/client_sharecap_wrapper_interface_${pcap}_output | awk '{print $7}'`
	mrss_sharecap_wrapper_interface=`grep "Maximum resident set size" res/client_sharecap_wrapper_interface_${pcap}_output | awk '{print $6/1024}'`
	utime_sharecap_wrapper_interface=`grep "User time" res/client_sharecap_wrapper_interface_${pcap}_output | awk '{print $4}'`
	stime_sharecap_wrapper_interface=`grep "System time" res/client_sharecap_wrapper_interface_${pcap}_output | awk '{print $4}'`
	xput_sharecap_wrapper_interface=`echo "$bytes_sharecap_wrapper_interface * 8 / ( $utime_sharecap_wrapper_interface + $stime_sharecap_wrapper_interface ) / 1000000" | bc -l`
	cpu_sharecap_wrapper_interface_master=`grep "Percent of CPU this job got" res/master_sharecap_wrapper_interface_${pcap}_output | awk '{print $7}'`
	mrss_sharecap_wrapper_interface_master=`grep "Maximum resident set size" res/master_sharecap_wrapper_interface_${pcap}_output | awk '{print $6/1024}'`
	utime_sharecap_wrapper_interface_master=`grep "User time" res/master_sharecap_wrapper_interface_${pcap}_output | awk '{print $4}'`
	stime_sharecap_wrapper_interface_master=`grep "System time" res/master_sharecap_wrapper_interface_${pcap}_output | awk '{print $4}'`
	xput_sharecap_wrapper_interface_master=`echo "$bytes_sharecap_wrapper_interface * 8 / ( $utime_sharecap_wrapper_interface_master + $stime_sharecap_wrapper_interface_master ) / 1000000" | bc -l`
	echo -e "sharecap_wrapper_interface_test\t${pcap}\tCPU: ${cpu_sharecap_wrapper_interface}\tSystem mem used: ${sys_mem_sharecap_wrapper_interface} MB\tMem: ${mem_sharecap_wrapper_interface} MB\tMRSS: ${mrss_sharecap_wrapper_interface} MB\tBytes: ${bytes_sharecap_wrapper_interface}\tPackets: ${pkts_sharecap_wrapper_interface}\tAverage packet size: ${pktsize_sharecap_wrapper_interface} bytes\tProcessing throughput: ${xput_sharecap_wrapper_interface} Mbps\tMaster CPU: ${cpu_sharecap_wrapper_interface_master}\tMaster mem usage: ${mem_sharecap_wrapper_interface_master} MB\tMaster MRSS: ${mrss_sharecap_wrapper_interface_master} MB\tMaster processing throughput: ${xput_sharecap_wrapper_interface_master} Mbps" >> results


	for ((i=0; i<options; i++)); do
		echo "Starting ${option[$i]} test"
		if [[ i -gt 1 ]]; then
			echo "Starting master"
			preload="LD_PRELOAD=../libpcap/libpcap.so"
			sudo /usr/bin/time -v ../test_sharecap/master -i eth0 -c 1 &> res/master_${option[$i]}_${pcap}_output &
			sleep 2
		else
			preload=""
		fi
		echo "Starting suricata"
		sudo $preload /usr/bin/time -v suricata -c /etc/suricata/suricata.yaml ${option_s[$i]} &> res/${option[$i]}_${pcap}_output &
		sleep 10
		echo "Playing $pcap from $replayer_box"
		ssh $replayer_box "sudo tcpreplay -i eth0 -t -l ${loops} /pcaps/${pcap} 2> /dev/null"
		echo "Played $pcap - stopping suricata"
		sys_mem_suricata=`free | grep Mem | awk '{print $3/1024}'`
		if [[ i -gt 1 ]]; then
			pid_master=`ps aux | grep "master -i" | grep -v time | grep -v grep | grep -v sudo | awk '{print $2}'`
			mem_suricata_master=`sudo pmap $pid_master | grep total | awk '{split($2,a,"K"); print a[1]/1024}'`
		fi
		pid_client=`ps aux | grep suricata | grep -v time | grep -v grep | grep -v sudo | awk '{print $2}'`
		mem_suricata=`sudo pmap $pid_client | grep total | awk '{split($2,a,"K"); print a[1]/1024}'`
		if [[ i -gt 1 ]]; then
			sudo kill -TERM $pid_master
			sleep 5
		fi
		sudo kill -TERM $pid_client
		sleep 30

		elapsed_suricata=`grep "Elapsed" res/${option[$i]}_${pcap}_output | awk '{split($8, a, ":"); print a[1]*60+a[2]}'`
		bytes_suricata=`grep bytes /var/log/suricata/stats.log | tail -1 | awk '{print $5}'`
		pkts_suricata=`grep pkts /var/log/suricata/stats.log | tail -1 | awk '{print $5}'`
		pktsize_suricata=`echo "$bytes_suricata / $pkts_suricata" | bc -l`
		flows1_suricata=`grep "flow.tcp" /var/log/suricata/stats.log | tail -1 | awk '{print $5}'`
		flows2_suricata=`grep "flow.udp" /var/log/suricata/stats.log | tail -1 | awk '{print $5}'`
		flows_suricata=`echo "$flows1_suricata + $flows2_suricata" | bc -l`
		flowsize_suricata=`echo "$bytes_suricata / $flows_suricata" | bc -l`
		flowssec_suricata=`echo "$flows_suricata / $elapsed_suricata" | bc -l`
		cpu_suricata=`grep "Percent of CPU this job got" res/${option[$i]}_${pcap}_output | awk '{print $7}'`
		mrss_suricata=`grep "Maximum resident set size" res/${option[$i]}_${pcap}_output | awk '{print $6/1024}'`
		utime_suricata=`grep "User time" res/${option[$i]}_${pcap}_output | awk '{print $4}'`
		stime_suricata=`grep "System time" res/${option[$i]}_${pcap}_output | awk '{print $4}'`
		xput_suricata=`echo "$bytes_suricata * 8 / ( $utime_suricata + $stime_suricata ) / 1000000" | bc -l`
		if [[ i -gt 1 ]]; then
			cpu_suricata_master=`grep "Percent of CPU this job got" res/master_${option[$i]}_${pcap}_output | awk '{print $7}'`
			mrss_suricata_master=`grep "Maximum resident set size" res/master_${option[$i]}_${pcap}_output | awk '{print $6/1024}'`
			utime_suricata_master=`grep "User time" res/master_${option[$i]}_${pcap}_output | awk '{print $4}'`
			stime_suricata_master=`grep "System time" res/master_${option[$i]}_${pcap}_output | awk '{print $4}'`
			xput_suricata_master=`echo "$bytes_suricata * 8 / ( $utime_suricata_master + $stime_suricata_master ) / 1000000" | bc -l`
			echo -e "${option[$i]}_test\t${pcap}\tCPU: ${cpu_suricata}\tSystem mem used: ${sys_mem_suricata} MB\tMem: ${mem_suricata} MB\tMRSS: ${mrss_suricata} MB\tBytes: ${bytes_suricata}\tPackets: ${pkts_suricata}\tAverage packet size: ${pktsize_suricata} bytes\tProcessing throughput: ${xput_suricata} Mbps\tMaster CPU: ${cpu_suricata_master}\tMaster mem usage: ${mem_suricata_master} MB\tMaster MRSS: ${mrss_suricata_master} MB\tMaster processing throughput: ${xput_suricata_master} Mbps\tFlows: ${flows_suricata}\tAverage flow size: ${flowsize_suricata} bytes\tFlows/sec: ${flowssec_suricata}" >> results
		else
			echo -e "${option[$i]}_test\t${pcap}\tCPU: ${cpu_suricata}\tSystem mem used: ${sys_mem_suricata} MB\tMem: ${mem_suricata} MB\tMRSS: ${mrss_suricata} MB\tBytes: ${bytes_suricata}\tPackets: ${pkts_suricata}\tAverage packet size: ${pktsize_suricata} bytes\tProcessing throughput: ${xput_suricata} Mbps\t\t\t\t\tFlows: ${flows_suricata}\tAverage flow size: ${flowsize_suricata} bytes\tFlows/sec: ${flowssec_suricata}" >> results
		fi

		sudo rm -rf /var/log/suricata/*
	done
done

rm -f capture_test_stats.csv
rm -rf res

