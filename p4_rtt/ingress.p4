/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
//#include <stdio.h>

const bit<32> TABLE_SIZE = 120;
const bit<32> C_THRESH = 1;
const bit<48> T_THRESH = 58561245452;
register<bit<32>>(TABLE_SIZE) arr;
register<bit<48>>(TABLE_SIZE) timestamp;
register<bit<32>>(1) total_flows;

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    bit<32> flow_cnt;
    bit<32>cnt;
    bit<48>current_timestamp;
    bit<48>previous_timestamp;

	action set_flowID(){
			meta.flowID = hdr.ipv4.srcAddr ++ hdr.ipv4.dstAddr ++ hdr.tcp.srcPort ++ hdr.tcp.dstPort;
	}

    action set_key(){
		hash(meta.hash_key,
			HashAlgorithm.crc32,
			32w0,
			{meta.flowID},
			TABLE_SIZE);
	}

	action count_flow(){
		set_flowID();
		set_key();
        current_timestamp = standard_metadata.ingress_global_timestamp;
        timestamp.read(previous_timestamp, meta.hash_key);
        arr.read(flow_cnt,meta.hash_key);
        total_flows.read(cnt,0);
        if(previous_timestamp == (bit<48>)0 || (current_timestamp - previous_timestamp ) < T_THRESH){
            if(flow_cnt == C_THRESH){
                cnt = cnt + 1;
            }
            else{
                flow_cnt = flow_cnt + 1;
            }
            // hdr.ethernet.srcAddr=(bit<48>)cnt;
        }
        else{
            flow_cnt = 0;
        }
        timestamp.write(meta.hash_key, current_timestamp);
        arr.write(meta.hash_key,flow_cnt);
        total_flows.write(0,cnt);
	}
    
    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action attach_ingress_global_timestamp(){
        hdr.ethernet.srcAddr = standard_metadata.ingress_global_timestamp;
    }

    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        count_flow();
    }

    table tcp_flag_ack_match {
		key = {
			hdr.tcp.ack: exact;
		}
		actions = {
			NoAction;
            attach_ingress_global_timestamp;
		}
		size = 2;
		default_action = attach_ingress_global_timestamp();
	}
    
    table forwarding {
        key = {
            standard_metadata.ingress_port:exact;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
			forwarding.apply();
		}
        else{
            drop();
        }
		if (hdr.tcp.isValid()) {
			if(hdr.tcp.rst != 1w1){
				tcp_flag_ack_match.apply();
			} else {
				drop();
			}
		}
    }
}

control MyIngressS1(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action attach_ingress_global_timestamp(){
        hdr.ethernet.srcAddr = standard_metadata.ingress_global_timestamp;
    }

    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table tcp_flag_ack_match {
		key = {
			hdr.tcp.ack: exact;
		}
		actions = {
			NoAction;
            attach_ingress_global_timestamp;
		}
		size = 2;
		default_action = attach_ingress_global_timestamp();
	}
    
    table forwarding {
        key = {
            standard_metadata.ingress_port:exact;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
			forwarding.apply();
		}
        else{
            drop();
        }
		if (hdr.tcp.isValid()) {
			if(hdr.tcp.rst != 1w1){
				tcp_flag_ack_match.apply();
			} else {
				drop();
			}
		}
    }
}
