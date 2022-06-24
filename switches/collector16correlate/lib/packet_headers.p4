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
    bit<32> src_addr;
    bit<32> dst_addr;
}

const bit<8> IPV4_MIN_HEAD_LEN = 20;

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_length;
    bit<16> checksum;
}

const bit<8> UDP_HEADER_LEN = 8;

header postcard_t {
    bit<32> sw_id;
    bit<32> flow_id;
    bit<8>  ttl;
    bit<48> ingress_tstamp;
    bit<48> egress_tstamp;
    bit<19> deq_depth;
    bit<19> enq_depth;
    bit<9> ingress_port;
    bit<9> egress_port;
}
#define POSTCARD_LEN_BYTES 28
#define POSTCARD_LEN_BITS 224

header aggregation_postcard_t {
    bit<8>  ttl;
    bit<48> ingress_tstamp;
    bit<48> egress_tstamp;
    bit<48> latency;
    bit<19> deq_depth;
    bit<19> enq_depth;
    bit<9> ingress_port;
    bit<9> egress_port;
}

#define AGGREGATION_POSTCARD_LEN_BYTES 26
#define AGGREGATION_POSTCARD_LEN_BITS 208


header telemetry_sum_t{
    bit<32> switch_id;
    bit<32> flow_id;
    bit<48> latency_min;
    bit<48> latency_max;
    bit<48> latency_avg;
    bit<19> enq_min;
    bit<19> enq_max;
    bit<19> enq_avg;
    bit<19> deq_min;
    bit<19> deq_max;
    bit<19> deq_avg;
    bit<6>  sum_of;
}
#define TELEMETRY_SUM_LEN_BYTES 41
#define TELEMETRY_SUM_LEN_BITS 328

struct headers_t {
    // ethernet header
    ethernet_t ethernet;
    ethernet_t xd_ethernet_header;
    // IPV4 header
    ipv4_t ipv4;
    ipv4_t xd_ip_header;
    // UDP header
    udp_t udp;
    udp_t xd_udp_header;
    // postcard headers
    postcard_t postcard;
    telemetry_sum_t telemetry_sum;
}


struct local_metadata_t {
    bit<1> is_postcard;
    bit<32> flow_id;
    bit<32> switch_id;
    bit<32> flow_register_number;
    bit<32> switch_register_number;
}

#endif
