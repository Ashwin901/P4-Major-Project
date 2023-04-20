/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
//#include <stdio.h>
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    
    action drop() {
        //printf("-----------------------------Hello world-------------------------\n");
        mark_to_drop(standard_metadata);
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
		}
		size = 2;
		default_action = NoAction();
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
		if (hdr.tcp.isValid()) {
			if(hdr.tcp.rst != 1w1){
				tcp_flag_ack_match.apply();
			} else {
				drop();
			}
		}
    }
}