
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
register<bit<48>>(1) process_delay;
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action delay(){
        hdr.ethernet.srcAddr = hdr.ethernet.srcAddr + standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp;
        process_delay.write(0,hdr.ethernet.srcAddr);
    }
   /* action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }*/
    table tcp_flag_ack_match {
		key = {
			hdr.tcp.ack: exact;
		}
		actions = {
			delay;
		}
		size = 2;
		default_action = delay();
	}
    /*
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
    */
    
    apply {
        /*
        if (hdr.ipv4.isValid()) {
			forwarding.apply();
		}
        */
		if (hdr.tcp.isValid()) {
			if(hdr.tcp.rst != 1w1){
				tcp_flag_ack_match.apply();
			} else {
				drop();
			}
		}
    }
}