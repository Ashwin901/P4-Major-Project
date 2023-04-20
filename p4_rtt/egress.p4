
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

register<bit<48>>(1) rtt_avg;
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action rtt(){
		bit<48> rtt_val;
		bit<48> x;
		bit<48> y;
		bit<48> rtt_prev;
		rtt_val=standard_metadata.egress_global_timestamp - hdr.ethernet.srcAddr;
		rtt_avg.read(rtt_prev,0);
		x=(rtt_val>>3);
		y=(rtt_prev>>3);
		
		if(rtt_prev==(bit<48>)0){
			
			rtt_prev=rtt_val;
		}
		else{
			rtt_prev=x + rtt_prev-y;
		}
		rtt_avg.write(0,rtt_prev);

        hdr.ethernet.srcAddr = rtt_prev;
    }
    table tcp_flag_ack_match {
		key = {
			hdr.tcp.ack: exact;
		}
		actions = {
			rtt;
            NoAction;
		}
		size = 2;
		default_action = NoAction();
	}
    apply {
		if (hdr.tcp.isValid()) {
			if(hdr.tcp.rst != 1w1){
				tcp_flag_ack_match.apply();
			} else {
				drop();
			}
		}
    }
}