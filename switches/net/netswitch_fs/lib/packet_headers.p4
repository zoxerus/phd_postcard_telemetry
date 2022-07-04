#ifndef __HEADERS__
#define __HEADERS__

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

header int_xd_t {
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

struct headers_t {
    ethernet_t xd_ethernet;
    ipv4_t xd_ipv4;
    udp_t xd_udp;
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    int_xd_t int_xd;
}

struct local_metadata_t {
    bit<1> mark_to_clone;
    @field_list(1)
    bit<48> ingress_tstamp;
    @field_list(1)
    bit<48> egress_tstamp;
    @field_list(1)
    bit<19> deq_qdepth;
    @field_list(1)
    bit<19> enq_qdepth;
    @field_list(1)
    bit<32> flow_id;
    @field_list(1)
    bit<8> ttl;
    @field_list(1)
    bit<9> ingress_port;
    @field_list(1)
    bit<9> egress_port;

}

#endif
