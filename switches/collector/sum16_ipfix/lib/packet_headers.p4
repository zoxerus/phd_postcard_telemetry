#ifndef __HEADERS__
#define __HEADERS__

#include "definitions.p4"

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}
#define ETH_LEN 14

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
    bit<32> src_addr;
    bit<32> dst_addr;
}
#define IPV4_MIN_LEN 20

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_length;
    bit<16> checksum;
}
#define UDP_LEN 8

header tcp_t{
    bit<16> src_port;
    bit<16> dst_port;
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
#define TCP_LEN 20





// the main header of an IPFIX message
struct ipfix_header_t{
    bit<16> version_number;
    bit<16> message_length;
    bit<32> export_time;
    bit<32> sequence_number;
    bit<32> observation_domain;
}

// the header of a set contained in the IPFIX message
struct set_header_t {
    bit<16> set_id;
    bit<16> set_length;
}

// header for a data record, that must be contained in the outward IPFIX message
struct record_sum_t {
    bit<32> collector_id;
    bit<32> flow_id;
    bit<8>  ttl;
    bit<48> latency_min;
    bit<48> latency_avg;
    bit<48> latency_max;
    bit<24> enq_min;
    bit<24> enq_avg;
    bit<24> enq_max;
    bit<24> deq_min;
    bit<24> deq_avg;
    bit<24> deq_max;
}
#define SET_SUM_ID 10256


// the data record of the incoming postcard, this data is extracted and then
// summerized in a new IPFIX message using the data_sum_t struct.
struct record_postcard_t {
    bit<32> flow_id;
    bit<8>  ttl;
    bit<48> ingress_tstamp;
    bit<48> egress_tstamp;
    bit<24> deq_depth;
    bit<24> enq_depth;
    bit<16> ingress_interface;
    bit<16> egress_interface;
}

header ipfix_postcard_t {
    ipfix_header_t     ipfix_header;
    set_header_t      set;
    record_postcard_t  record;
}

header ipfix_sum_t {
    ipfix_header_t  ipfix_header;
    set_header_t    set;
    record_sum_t    record;
}
#define SET_SUM_LEN 46
#define IPFIX_SUM_LEN 65


// the headers that are used by the switch.
struct headers_t {
    ethernet_t xd_ethernet;
    ipv4_t xd_ipv4;
    udp_t xd_udp;

    ipfix_postcard_t ipfix_postcard;
    ipfix_sum_t      ipfix_sum;

    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
}


// a user metadata
struct local_metadata_t {
    bit<1> is_postcard;
    bit<32> flow_id;
    bit<32> switch_id;
    bit<32> flow_register_number;
    bit<32> switch_register_number;
}

#endif
