register_names="src_ip dst_ip src_port dst_port protos tos_register syn_counter psh_counter ack_counter flow_total_length forward_total_length fw_win_byt flow_duration flow_min_duration flow_total_active_duration flow_active_segments flow_total_inactive_duration subflow_fwd_bytes is_inactive flow_start_time_stamp"

for r in `echo $register_names | awk -F' ' '{for(i=1;i<=NF;i++) print $i}'`
do
	echo "copyind data for register $r to $r.txt"
	echo "register_read $r" | simple_switch_CLI --thrift-port 9090 | grep "=" | cut -d"=" -f2 > $r.txt	      						
	echo $?
done
