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
#define SET_SUM_ID 1256

header ipfix_postcard_t {
    ipfix_header_t     ipfix_header;
    set_header_t      set;
    record_postcard_t  record;
}

header ipfix_agg_t {
    ipfix_header_t  ipfix_header;
    set_header_t    set;
    record_postcard_t[PACKET_AGGREGATOR_THRESHOLD] record;
}
#define SET_AGG_LEN 532
#define IPFIX_AGG_LEN 548


// the headers that are used by the switch.
struct headers_t {
    ethernet_t xd_ethernet;
    ipv4_t xd_ipv4;
    udp_t xd_udp;

    ipfix_postcard_t ipfix_postcard;
    ipfix_agg_t      ipfix_agg;

    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
}


// a user metadata
struct local_metadata_t {
    @field_list (1)
    bit<1> is_postcard;
    @field_list (1)
    bit<32> switch_id;
    @field_list (1)
    bit<32> switch_register_number;
}

#endif
