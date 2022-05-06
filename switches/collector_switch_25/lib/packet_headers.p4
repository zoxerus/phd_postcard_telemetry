#ifndef __HEADERS__
#define __HEADERS__

#include "definitions.p4"

///// Ethernet Header ////////
header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}
const bit<8> ETH_HEADER_LEN = 14;
/// ########### #########  //

///// IPV4 Header //////////////
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}
const bit<8> IPV4_MIN_HEAD_LEN = 20;
///////////// ################## ///////////


///// UDP Header /////////////////
header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_length;
    bit<16> checksum;
}
const bit<8> UDP_HEADER_LEN = 8;
//////// ################## //////


header int_xd_in_t {
    bit<32> switch_id;
    bit<32> flow_id;
    bit<8>  ttl;
    bit<48> ingress_tstamp;
    bit<48> egress_tstamp;
    bit<19> deq_depth;
    bit<19> enq_depth;
    bit<9> ingress_port;
    bit<9> egress_port;
}

#define REPORT_FIXED_HEADER_LEN_BITS 224
#define REPORT_FIXED_HEADER_LEN_BYTES 28




// a header field for aggregating the telemetry packets sent to collector


const bit<3> NPROTO_ETHERNET = 0;

/////// Report Telemetry Headers ///////
// header report_fixed_header_t {
//     bit<4>  ver;
//     bit<4>  len;
//     bit<3>  nproto;
//     bit<6>  rep_md_bits;
//     bit<1>  d;
//     bit<1>  q;
//     bit<1>  f;
//     bit<6>  rsvd;
//     bit<6>  hw_id;
//     bit<32> sw_id;
//     bit<32> seq_no;
//     bit<32> ingress_tstamp;
//     bit<32> engress_tstamp;
// }
// #define REPORT_FIXED_HEADER_LEN_BITS 160
// #define REPORT_FIXED_HEADER_LEN_BYTES 20
////// ################## ///////////////

/////// Aggregated Header /////////////
header telemetry_aggregated_header_t{
    bit<REPORT_FIXED_HEADER_LEN_BITS> one_field;
}
/////////////////////////////////////////////////



struct headers_t {
    // ethernet header
    ethernet_t ethernet;
    // IPV4 header
    ipv4_t ipv4;
    // UDP header
    udp_t udp;
    // postcard header
    int_xd_t int_xd;
    // aggregated-postcards header
    telemetry_aggregated_header_t[PACKET_AGGREGATOR_THRESHOLD] telemetry_aggregated_header;
}

//////  User metadate /////////
struct local_metadata_t {
    bit<1> is_postcard;
    bit<1> is_forwarded;
}
//////////////////////////////////

#endif
