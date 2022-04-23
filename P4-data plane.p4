/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_ARP = 0x806;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;

#define REGISTER_LENGTH 100000
#define TIMESTAMP_WIDTH 48
#define IDLE_TIMEOUT 5000000

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ipv6_addr;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ieee_t {
    macAddr_t addr1;
    macAddr_t addr2;
    macAddr_t addr3;
    macAddr_t addr4;
    bit<16>   ieeeType;

}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// struct ipv6_addr {
//     bit<32> Addr0;
//     bit<32> Addr1;
//     bit<32> Addr2;
//     bit<32> Addr3;
// }

header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payloadLen;
    bit<8>    nextHdr;
    bit<8>    hopLimit;
    ipv6_addr srcAddr;
    ipv6_addr dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;

}

header udp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
    }

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
    tcp_t        tcp;
    udp_t        udp;
    ieee_t       ieee;
    // vlan_tag_t       vlan;
    // arp_rarp_t       arp;
    // arp_rarp_ipv4_t  arp_ipv4;
}

struct metadata {
    /* empty */
    bit<64> tmp_counter;
    bit<64> syn_bit;
    bit<64> psh_bit;
    bit<64> ack_bit;
    bit<64> packet_protocol;
    ip4Addr_t ipAddr;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
    ipv6_addr ipAddr2;
    ipv6_addr srcAddr2;
    ipv6_addr dstAddr2;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> flowlet_register_index;
    bit<64>isForward;
    bit<32>  ipcache_index;
    bit<64> tmpWindow;
    bit<64> flowlet_last_stamp;
    bit<64> val;
    ip4Addr_t hash_srcAddr;
    ip4Addr_t hash_dstAddr;
    ipv6_addr hash_srcAddr2;
    ipv6_addr hash_dstAddr2;
    bit<16> hash_srcPort;
    bit<16> hash_dstPort;
    bit<64> flowlet_time_diff;
    bit<64> flowlet_active_time_diff;
    bit<64> flowlet_inactive_time_diff;
    bit<64> flowlet_active_start_stamp;
    bit<64> inactive_bit;

    
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser Myparser2(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
                    state start {

        packet.extract(hdr.ieee);

        transition select(hdr.ieee.ieeeType){

            TYPE_IPV4: ipv4;
            TYPE_IPV6: ipv6;                                             
            default: accept;
        }

        
    }

    state ipv4 {
        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            default: accept;
        }
    }

    state ipv6 {
        packet.extract(hdr.ipv6);

        transition select(hdr.ipv6.nextHdr){
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            default: accept;
        }
    }


    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }
    

    state udp {
    packet.extract(hdr.udp);
    transition accept;
    }

                }

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

                    Myparser2() subparser;
                    state subroutine {
          subparser.apply(packet, hdr,meta,standard_metadata);  // invoke sub-parser
          transition accept;  // accept if sub-parser ends in accept state
     }

    state start {

        packet.extract(hdr.ethernet);

        transition select(hdr.ethernet.etherType){

            TYPE_IPV4: ipv4;
            TYPE_IPV6: ipv6;
            // ETHERTYPE_VLAN : vlan;     
            // ETHERTYPE_ARP : arp;                                        
            default: accept;
        }

        
    }

    state ipv4 {
        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            default: accept;
        }
    }

    state ipv6 {
        packet.extract(hdr.ipv6);

        transition select(hdr.ipv6.nextHdr){
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            default: accept;
        }
    }


    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }
    

    state udp {
    packet.extract(hdr.udp);
    transition accept;
    }
}




/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    register<bit<64>>(REGISTER_LENGTH) tos_register;
    register<bit<64>>(REGISTER_LENGTH) protos;
    register<bit<128>>(REGISTER_LENGTH) src_ip;
    register<bit<128>>(REGISTER_LENGTH) dst_ip;
    register<bit<64>>(REGISTER_LENGTH) src_port;
    register<bit<64>>(REGISTER_LENGTH) dst_port;
    register<bit<64>>(REGISTER_LENGTH) syn_counter;
    register<bit<64>>(REGISTER_LENGTH) psh_counter;
    register<bit<64>>(REGISTER_LENGTH) ack_counter;
    register<bit<64>>(REGISTER_LENGTH) flow_total_length;
    register<bit<32>>(REGISTER_LENGTH) ipaddr_cache;
    register<bit<128>>(REGISTER_LENGTH) ipaddr6_cache;
    register<bit<64>>(REGISTER_LENGTH) forward_total_length;
    register<bit<64>>(REGISTER_LENGTH) fw_win_byt;
    register<bit<64>>(REGISTER_LENGTH) flow_start_time_stamp;
    register<bit<64>>(REGISTER_LENGTH) flow_duration;
    register<bit<64>>(REGISTER_LENGTH) flow_active_start_time_stamp;
    register<bit<64>>(REGISTER_LENGTH) flow_total_active_duration;
    register<bit<64>>(REGISTER_LENGTH) flow_total_inactive_duration;
    register<bit<64>>(REGISTER_LENGTH) flow_active_segments;
    register<bit<64>>(REGISTER_LENGTH) flow_min_duration;
    register<bit<64>>(REGISTER_LENGTH) subflow_fwd_bytes;
    register<bit<64>>(REGISTER_LENGTH) is_inactive;

    action get_metrics_ipv4()
    {
            meta.syn_bit = 0;
            meta.psh_bit = 0;
            meta.ack_bit = 0;

            hash(meta.ipcache_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{hdr.ipv4.srcAddr, hdr.ipv4.dstAddr},
			(bit<14>)8192);
		ipaddr_cache.read(meta.ipAddr, meta.ipcache_index);

        if (meta.ipAddr == hdr.ipv4.srcAddr || meta.ipAddr == 0) {
				meta.isForward = 1;  // its a forward packet
		} 


        hash(meta.ipcache_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{hdr.ipv4.dstAddr, hdr.ipv4.srcAddr},
			(bit<14>)8192);
		ipaddr_cache.read(meta.ipAddr, meta.ipcache_index);
		if (meta.ipAddr == hdr.ipv4.dstAddr) {
				meta.isForward = 0;  // its a backward packet
		} else {
				// its a new flow, so a forward packet
				meta.isForward = 1;
		}

        if(meta.isForward == 1) {
				meta.ipAddr = hdr.ipv4.srcAddr;
				meta.dstAddr = hdr.ipv4.dstAddr;
		} else {
				meta.ipAddr = hdr.ipv4.dstAddr;
				meta.dstAddr = hdr.ipv4.srcAddr;
		}
		
		hash(meta.ipcache_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{meta.ipAddr, meta.dstAddr},
			(bit<14>)8192);
		ipaddr_cache.write(meta.ipcache_index, meta.ipAddr);
		// end-of-flow direction	


		// find the register index for this flow
		if (meta.isForward == 1) {
				meta.srcAddr = hdr.ipv4.srcAddr;
				meta.dstAddr = hdr.ipv4.dstAddr;
                if(hdr.tcp.isValid()){
				meta.srcPort = hdr.tcp.srcPort;
				meta.dstPort = hdr.tcp.dstPort;
                }
                if(hdr.udp.isValid()){
				meta.srcPort = hdr.udp.srcPort;
				meta.dstPort = hdr.udp.dstPort;
                }

		} else {
				meta.srcAddr = hdr.ipv4.dstAddr;
				meta.dstAddr = hdr.ipv4.srcAddr;
				if(hdr.tcp.isValid()){
				meta.srcPort = hdr.tcp.dstPort;
				meta.dstPort = hdr.tcp.srcPort;
                }
                if(hdr.udp.isValid()){
				meta.srcPort = hdr.udp.dstPort;
				meta.dstPort = hdr.udp.srcPort;
                }
		}	


            // meta.srcAddr = hdr.ipv4.srcAddr;
            // meta.dstAddr = hdr.ipv4.dstAddr;
            if(hdr.tcp.isValid()){
            // meta.srcPort = hdr.tcp.srcPort;
            // meta.dstPort = hdr.tcp.dstPort;
            if(hdr.tcp.syn == 1)
                {
              meta.syn_bit = 1; 
              }
            if(hdr.tcp.psh == 1)
                {
              meta.psh_bit = 1; 
              }
              if(hdr.tcp.ack == 1)
                {
              meta.ack_bit = 1; 
              }
            }
            // if(hdr.udp.isValid()){
            // meta.srcPort = hdr.udp.srcPort;
            // meta.dstPort = hdr.udp.dstPort;
            // }

            //Separate ips and ports for hashing to account for bidirectional flows
            if(meta.srcAddr <= meta.dstAddr)
            {
                meta.hash_srcAddr = meta.srcAddr;
                meta.hash_dstAddr = meta.dstAddr;
            }
            else
            {
                meta.hash_srcAddr = meta.dstAddr;
                meta.hash_dstAddr = meta.srcAddr;
            }

            if(meta.srcPort <= meta.dstPort)
            {
                meta.hash_srcPort = meta.srcPort;
                meta.hash_dstPort = meta.dstPort;
            }
            else
            {
                meta.hash_srcPort = meta.dstPort;
                meta.hash_dstPort = meta.srcPort;
            }


            hash(meta.flowlet_register_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{meta.hash_srcAddr, meta.hash_dstAddr, meta.hash_srcPort, meta.hash_dstPort,hdr.ipv4.protocol},
			(bit<14>)8192);

            //Per Flow Packet counts
            tos_register.read(meta.tmp_counter, meta.flowlet_register_index);
            meta.tmp_counter = meta.tmp_counter + 1;
            tos_register.write(meta.flowlet_register_index, meta.tmp_counter);

            //1. TCP Syn Counter
            syn_counter.read(meta.tmp_counter, meta.flowlet_register_index);
            meta.tmp_counter = meta.tmp_counter + meta.syn_bit;
            syn_counter.write(meta.flowlet_register_index, meta.tmp_counter);

            //2. TCP PSH Counter
            psh_counter.read(meta.tmp_counter, meta.flowlet_register_index);
            meta.tmp_counter = meta.tmp_counter + meta.psh_bit;
            psh_counter.write(meta.flowlet_register_index, meta.tmp_counter);

            //3. TCP ACK Counter
            ack_counter.read(meta.tmp_counter, meta.flowlet_register_index);
            meta.tmp_counter = meta.tmp_counter + meta.ack_bit;
            ack_counter.write(meta.flowlet_register_index, meta.tmp_counter);

            //4. Average Flow Length (Total Flow Length/No of Packets per flow)
            flow_total_length.read(meta.tmp_counter, meta.flowlet_register_index);
		    meta.tmp_counter = meta.tmp_counter + (bit<64>)hdr.ipv4.totalLen;
		    flow_total_length.write(meta.flowlet_register_index, meta.tmp_counter);

            //5. Total Length in a Forward Flow
            forward_total_length.read(meta.tmp_counter, meta.flowlet_register_index);
            if (meta.isForward == 1) {
                    meta.tmp_counter = meta.tmp_counter + (bit<64>)hdr.ipv4.totalLen;
            }
            forward_total_length.write(meta.flowlet_register_index, meta.tmp_counter);

            //6. Initial Window Size of a forward flow
            fw_win_byt.read(meta.tmpWindow, meta.flowlet_register_index);
            if(hdr.tcp.isValid()){
            if (meta.isForward ==1 && meta.tmpWindow == 0) {
                    meta.tmpWindow = (bit <64>)hdr.tcp.window;
            }	
            }
            fw_win_byt.write(meta.flowlet_register_index, meta.tmpWindow);
            meta.tmpWindow = 0;


            //7. Flow Duration --> Store Start Time Stamps and Current Time Stamps
            flow_start_time_stamp.read(meta.flowlet_last_stamp, meta.flowlet_register_index);
            if(meta.flowlet_last_stamp == 0) {
                    meta.flowlet_last_stamp = (bit<64>)(standard_metadata.ingress_global_timestamp);
            }	
            flow_start_time_stamp.write(meta.flowlet_register_index, meta.flowlet_last_stamp);
            
        
            meta.val = (bit<64>)((bit<64>)(standard_metadata.ingress_global_timestamp) - meta.flowlet_last_stamp);
            flow_duration.write(meta.flowlet_register_index, meta.val);


            protos.write(meta.flowlet_register_index, (bit<64>)(hdr.ipv4.protocol));
            src_ip.write(meta.flowlet_register_index, (bit<128>)(meta.hash_srcAddr));
            dst_ip.write(meta.flowlet_register_index, (bit<128>)(meta.hash_dstAddr));
            src_port.write(meta.flowlet_register_index, (bit<64>)(meta.hash_srcPort));
            dst_port.write(meta.flowlet_register_index, (bit<64>)(meta.hash_dstPort));
    }

    action get_metrics_ipv6()
    {
        meta.syn_bit = 0;
            meta.psh_bit = 0;
            meta.ack_bit = 0;

            hash(meta.ipcache_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{hdr.ipv6.srcAddr, hdr.ipv6.dstAddr},
			(bit<14>)8192);
		ipaddr6_cache.read(meta.ipAddr2, meta.ipcache_index);

        if (meta.ipAddr2 == hdr.ipv6.srcAddr || meta.ipAddr2 == 0) {
				meta.isForward = 1;  // its a forward packet
		} 


        hash(meta.ipcache_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{hdr.ipv6.dstAddr, hdr.ipv6.srcAddr},
			(bit<14>)8192);
		ipaddr6_cache.read(meta.ipAddr2, meta.ipcache_index);
		if (meta.ipAddr2 == hdr.ipv6.dstAddr) {
				meta.isForward = 0;  // its a backward packet
		} else {
				// its a new flow, so a forward packet
				meta.isForward = 1;
		}

        if(meta.isForward == 1) {
				meta.ipAddr2 = hdr.ipv6.srcAddr;
				meta.dstAddr2 = hdr.ipv6.dstAddr;
		} else {
				meta.ipAddr2 = hdr.ipv6.dstAddr;
				meta.dstAddr2 = hdr.ipv6.srcAddr;
		}
		
		hash(meta.ipcache_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{meta.ipAddr2, meta.dstAddr2},
			(bit<14>)8192);
		ipaddr6_cache.write(meta.ipcache_index, meta.ipAddr2);
		// end-of-flow direction	


		// find the register index for this flow
		if (meta.isForward == 1) {
				meta.srcAddr2 = hdr.ipv6.srcAddr;
				meta.dstAddr2 = hdr.ipv6.dstAddr;
                if(hdr.tcp.isValid()){
				meta.srcPort = hdr.tcp.srcPort;
				meta.dstPort = hdr.tcp.dstPort;
                }
                if(hdr.udp.isValid()){
				meta.srcPort = hdr.udp.srcPort;
				meta.dstPort = hdr.udp.dstPort;
                }

		} else {
				meta.srcAddr2 = hdr.ipv6.dstAddr;
				meta.dstAddr2 = hdr.ipv6.srcAddr;
				if(hdr.tcp.isValid()){
				meta.srcPort = hdr.tcp.dstPort;
				meta.dstPort = hdr.tcp.srcPort;
                }
                if(hdr.udp.isValid()){
				meta.srcPort = hdr.udp.dstPort;
				meta.dstPort = hdr.udp.srcPort;
                }
		}	

            
            if(hdr.tcp.isValid()){
            
            if(hdr.tcp.syn == 1)
                {
              meta.syn_bit = 1; 
              }
            if(hdr.tcp.psh == 1)
                {
              meta.psh_bit = 1; 
              }
              if(hdr.tcp.ack == 1)
                {
              meta.ack_bit = 1; 
              }
            }
            

            if(meta.srcAddr2 <= meta.dstAddr2)
            {
                meta.hash_srcAddr2 = meta.srcAddr2;
                meta.hash_dstAddr2 = meta.dstAddr2;
            }
            else
            {
                meta.hash_srcAddr2 = meta.dstAddr2;
                meta.hash_dstAddr2 = meta.srcAddr2;
            }

            if(meta.srcPort <= meta.dstPort)
            {
                meta.hash_srcPort = meta.srcPort;
                meta.hash_dstPort = meta.dstPort;
            }
            else
            {
                meta.hash_srcPort = meta.dstPort;
                meta.hash_dstPort = meta.srcPort;
            }


            hash(meta.flowlet_register_index, HashAlgorithm.crc16,
			(bit<16>)0,
			{meta.hash_srcAddr2, meta.hash_dstAddr2, meta.hash_srcPort, meta.hash_dstPort,hdr.ipv6.nextHdr},
			(bit<14>)8192);

            //Total packets per flow
            tos_register.read(meta.tmp_counter, meta.flowlet_register_index);
            meta.tmp_counter = meta.tmp_counter + 1;
            tos_register.write(meta.flowlet_register_index, meta.tmp_counter);
            
            //1. SYN Counter per flow
            syn_counter.read(meta.tmp_counter, meta.flowlet_register_index);
            meta.tmp_counter = meta.tmp_counter + meta.syn_bit;
            syn_counter.write(meta.flowlet_register_index, meta.tmp_counter);

            //2. PSH Counter per flow
            psh_counter.read(meta.tmp_counter, meta.flowlet_register_index);
            meta.tmp_counter = meta.tmp_counter + meta.psh_bit;
            psh_counter.write(meta.flowlet_register_index, meta.tmp_counter);

            //3. ACK Counter per flow
            ack_counter.read(meta.tmp_counter, meta.flowlet_register_index);
            meta.tmp_counter = meta.tmp_counter + meta.ack_bit;
            ack_counter.write(meta.flowlet_register_index, meta.tmp_counter);

            //4. Flow Average Length = Flow Total Length/Packets per flow
            flow_total_length.read(meta.tmp_counter, meta.flowlet_register_index);
		    meta.tmp_counter = meta.tmp_counter + (bit<64>)hdr.ipv6.payloadLen;
		    flow_total_length.write(meta.flowlet_register_index, meta.tmp_counter);

            //5. Forward Flow Total Length
            forward_total_length.read(meta.tmp_counter, meta.flowlet_register_index);
            if (meta.isForward == 1) {
                    meta.tmp_counter = meta.tmp_counter + (bit<64>)hdr.ipv6.payloadLen;
            }
            forward_total_length.write(meta.flowlet_register_index, meta.tmp_counter);

            //6. Init Window for Forward Flow
            fw_win_byt.read(meta.tmpWindow, meta.flowlet_register_index);
            if(hdr.tcp.isValid()){
            if (meta.isForward ==1 && meta.tmpWindow == 0) {
                    meta.tmpWindow = (bit<64>)hdr.tcp.window;
            }	
            }
            fw_win_byt.write(meta.flowlet_register_index, meta.tmpWindow);
            meta.tmpWindow = 0;

            // forward_total_packets.read(meta.tmp_counter, meta.flowlet_register_index);
            // if (meta.isForward == 1) {
            //         meta.tmp_counter = meta.tmp_counter + 1;
            // }
            // forward_total_packets.write(meta.flowlet_register_index, meta.tmp_counter);


            //7. Flow Duration
            flow_start_time_stamp.read(meta.flowlet_last_stamp, meta.flowlet_register_index);
            if(meta.flowlet_last_stamp == 0) {
                    meta.flowlet_last_stamp = (bit<64>)(standard_metadata.ingress_global_timestamp);
            }	
            flow_start_time_stamp.write(meta.flowlet_register_index, meta.flowlet_last_stamp);
            
        
            meta.val = (bit<64>)((bit<64>)(standard_metadata.ingress_global_timestamp) - meta.flowlet_last_stamp);
            flow_duration.write(meta.flowlet_register_index, meta.val);

            // flow_current_time_stamp.read(meta.flowlet_last_stamp, meta.flowlet_register_index);
            // if(meta.flowlet_last_stamp == 0) {
            //         meta.flowlet_last_stamp = (bit<64>)(standard_metadata.ingress_global_timestamp);
            // }	
            // flow_current_time_stamp.write(meta.flowlet_register_index, (bit <64>)standard_metadata.ingress_global_timestamp);

            // enq_time_stamp.write(meta.flowlet_register_index, (bit<64>)standard_metadata.deq_timestamp);

            protos.write(meta.flowlet_register_index, (bit<64>)(hdr.ipv6.nextHdr));
            src_ip.write(meta.flowlet_register_index, (bit<128>)(meta.hash_srcAddr2));
            dst_ip.write(meta.flowlet_register_index, (bit<128>)(meta.hash_dstAddr2));
            src_port.write(meta.flowlet_register_index, (bit<64>)(meta.hash_srcPort));
            dst_port.write(meta.flowlet_register_index, (bit<64>)(meta.hash_dstPort));
    }

    action update_flow_metrics()
    {
        //8. Active Min Duration
        flow_min_duration.read(meta.val, meta.flowlet_register_index);
        if(meta.val == 0)
        {
            meta.val = (bit<64>)meta.flowlet_time_diff;
        }
        else{
		if (meta.val > (bit<64>)meta.flowlet_time_diff) {
				meta.val = (bit<64>)meta.flowlet_time_diff;		
		}	
        }
		flow_min_duration.write(meta.flowlet_register_index, meta.val);


		//9. Active Mean Duration = Flow Total Active Duration/No of active segments
		// add current active duration
		flow_total_active_duration.read(meta.tmp_counter, meta.flowlet_register_index);
		meta.tmp_counter = meta.tmp_counter + (bit<64>)meta.flowlet_time_diff;
		flow_total_active_duration.write(meta.flowlet_register_index, meta.tmp_counter);
			
	
		// add number of segments
		flow_active_segments.read(meta.tmp_counter, meta.flowlet_register_index);
		meta.tmp_counter = meta.tmp_counter + 1;
		flow_active_segments.write(meta.flowlet_register_index, meta.tmp_counter);

		// 10. Flow Inter Arrival Time
		flow_total_inactive_duration.read(meta.tmp_counter, meta.flowlet_register_index);
		meta.tmp_counter = meta.tmp_counter +  (bit<64>)standard_metadata.ingress_global_timestamp;
		flow_total_inactive_duration.write(meta.flowlet_register_index, meta.tmp_counter);

        //11. Subflow Fwd Bytes
        subflow_fwd_bytes.read(meta.tmp_counter, meta.flowlet_register_index);
        if(meta.isForward==1)
        {
            if(hdr.ipv4.isValid())
                meta.tmp_counter = meta.tmp_counter +  (bit<64>)hdr.ipv4.totalLen;
            if(hdr.ipv6.isValid())
                meta.tmp_counter = meta.tmp_counter +  (bit<64>)hdr.ipv6.payloadLen;
        }
        subflow_fwd_bytes.write(meta.flowlet_register_index, meta.tmp_counter);

        //  reset the active start time
		flow_active_start_time_stamp.write(meta.flowlet_register_index, (bit<64>)standard_metadata.ingress_global_timestamp);
    }


    // action drop() {
    //     mark_to_drop(standard_metadata);
    // }


    // action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {

    //     //set the src mac address as the previous dst, this is not correct right?
    //     hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

    //    //set the destination mac address that we got from the match in the table
    //     hdr.ethernet.dstAddr = dstAddr;

    //     //set the output port that we also get from the table
    //     standard_metadata.egress_spec = port;

    //     //decrease ttl by 1
    //     hdr.ipv4.ttl = hdr.ipv4.ttl -1;

    // }


    // table ipv4_lpm {
    //     key = {
    //         hdr.ipv4.dstAddr: lpm;
    //     }
    //     actions = {
    //         ipv4_forward;
    //         drop;
    //         NoAction;
    //     }
    //     size = 1024;
    //     default_action = NoAction();
    // }


    // table drop_table{
    //     actions = {
    //         drop;
    //     }
    //     size =1;
    //     default_action = drop();
    // }

    apply {
        if (hdr.ipv4.isValid()){
            
            get_metrics_ipv4();
        }
        if(hdr.ipv6.isValid()){
             
           get_metrics_ipv6();
        }

        meta.flowlet_time_diff = meta.flowlet_last_stamp - meta.flowlet_active_start_stamp;
        meta.flowlet_inactive_time_diff = (bit<64>)standard_metadata.ingress_global_timestamp - meta.flowlet_last_stamp;
        
        // check if inter-packet gap is > 1sec
        if (meta.flowlet_inactive_time_diff > IDLE_TIMEOUT){
            is_inactive.read(meta.inactive_bit, meta.flowlet_register_index);
            meta.inactive_bit = 1;
            is_inactive.write(meta.flowlet_register_index, meta.inactive_bit);
            update_flow_metrics();
        }
        
    }

                  }            

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.tos,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

//        parsed headers have to be added again into the packet.
        // packet.emit(hdr.ethernet);
        // packet.emit(hdr.ipv4);
        // packet.emit(hdr.ipv6);
        // packet.emit(hdr.tcp);
        // packet.emit(hdr.udp);
        packet.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
