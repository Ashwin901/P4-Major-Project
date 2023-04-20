const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_UDP = 0x11;
const bit<8> TYPE_TCP = 0x06;
const bit<16> TYPE_RTP = 0x138C;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
   macAddr_t dstAddr;
   macAddr_t srcAddr;
   bit<16>   etherType;
}

header ipv4_t {
   bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
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

header udp_t {
    bit<16>   srcPort;
    bit<16>   destPort;
    bit<16>   udpLength;
    bit<16>   udpChecksum;
}

header tcp_t {
    /*
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<12> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
    bit<32> tsVal;
    bit<32> tsEcr;
    */
    bit<16> srcPort;
	bit<16> dstPort;
	bit<32> seqNo;
	bit<32> ackNo;
	bit<4>  dataOffset;
	bit<3>  res;
	bit<3>  ecn;
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

header rtp_t {
    bit<2> rtpVersion;
    bit<1> p;
    bit<1> x;
    bit<2> cc;
    bit<1> m;
    bit<9> pt;
    bit<16> seqNumber;
    bit<32> timestamp;
    bit<32> ssrc;
}

struct metadata {
      /* flow id */
	bit<96> flowID;
	/* hash of flow */
	bit<32> hash_key;
	//bit<10> arr[10];
	/* expected ack hash */
	bit<32> eACK;
	/* size of packet payload */
	bit<32> payload_size;

	#ifdef MSS_FLAG
	//separate identifier for MSS table
	bit<MSSID_BITS> mssID;
	bit<32> mss_key;
	#endif

	#ifdef SUBSAMPLE_FLAG
	//p4-16 runtime doesn't allow boolean values in header/metadata
	/* flag if packet is being sampled */
	bit<1> sampled;
	#endif
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    tcp_t        tcp;
    rtp_t        rtp;
}

