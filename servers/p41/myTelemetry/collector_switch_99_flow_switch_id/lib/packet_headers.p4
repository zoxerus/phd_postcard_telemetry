#ifndef __HEADERS__
#define __HEADERS__

#include "definitions.p4"

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}
const bit<8> ETH_HEADER_LEN = 14;

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

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_length;
    bit<16> checksum;
}

const bit<8> UDP_HEADER_LEN = 8;

// header int_xd_t {
//     bit<32> switch_id;
//     bit<32> flow_id;
//     bit<8>  ttl;
//     bit<48> latency;
//     bit<24> deq_depth;
//     bit<24> enq_depth;
// }
//
// #define INT_XD_HEADER_LENGTH 168


// a header field for aggregating the telemetry packets sent to collector


const bit<3> NPROTO_ETHERNET = 0;

// Report Telemetry Headers
header report_fixed_header_t {
    bit<4>  ver;            //version
    bit<4>  len;            //lenght of the report header in multiples of 4 octets
    bit<3>  nproto;         // next protocol 0: Ethernet, 1: IPv4, 2: IPv6
    bit<6>  rep_md_bits;    //report metadata, see p4 telemetry report specifications
    bit<1>  d;              // dropped packets
    bit<1>  q;              // congested queue
    bit<1>  f;              // indicates a packet for a tracked flow
    bit<6>  rsvd;           //reserved
    bit<6>  hw_id;          // identifies the hardware subsystem
    bit<32> sw_id;          // switch id
    bit<32> seq_no;         // report sequence number, here is used as a flow id
    bit<32> ingress_tstamp; // ingress timestamp
    bit<32> engress_tstamp; // egress timestamp
}
#define REPORT_FIXED_HEADER_LEN_BITS 160
#define REPORT_FIXED_HEADER_LEN_BYTES 20

header telemetry_header_t{
    bit<32> switch_id;
    bit<32> flow_id;
    bit<32> latency_average;
}
header telemetry_aggregated_header_t{
    bit<32> one_field;
}


struct headers_t {
    // ethernet header
    ethernet_t ethernet;
    // IPV4 header
    ipv4_t ipv4;
    // UDP header
    udp_t udp;
    // postcard header
    report_fixed_header_t int_xd;

    telemetry_header_t telemetry_header;
    // aggregated-postcards header
    telemetry_aggregated_header_t[PACKET_AGGREGATOR_THRESHOLD] telemetry_aggregated_header;
}


struct local_metadata_t {
    bit<1> is_postcard;
    bit<32> flow_id;
    bit<32> switch_id;
    bit<32> flow_register_number;
    bit<32> switch_register_number;
}

#endif
