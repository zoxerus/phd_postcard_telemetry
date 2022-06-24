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
const bit<8> TCP_HEADER_LENGTH_BITS = 160;
const bit<8> TCP_HEADER_LENGTH_BYTES = 20;

// header int_xd_t {
//     bit<32> switch_id;
//     bit<32> flow_id;
//     bit<8>  ttl;
//     bit<48> latency;
//     bit<24> deq_depth;
//     bit<24> enq_depth;
// }
//
// const bit<8> INT_XD_HEADER_LENGTH = 164;

const bit<3> NPROTO_ETHERNET = 0;

// Report Telemetry Headers
header report_fixed_header_t {
    bit<4>  ver;
    bit<4>  len;
    bit<3>  nproto;
    bit<6>  rep_md_bits;
    bit<1>  d;
    bit<1>  q;
    bit<1>  f;
    bit<6>  rsvd;
    bit<6>  hw_id;
    bit<32> sw_id;
    bit<32> seq_no;
    bit<32> ingress_tstamp;
    bit<32> engress_tstamp;
}
#define REPORT_FIXED_HEADER_LEN_BITS 160
#define REPORT_FIXED_HEADER_LEN_BYTES 20

struct headers_t {
    ethernet_t xd_ethernet;
    ipv4_t xd_ipv4;
    udp_t xd_udp;
    report_fixed_header_t int_xd;
    
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    tcp_t tcp;
}

struct local_metadata_t {
    @field_list(1)
    bit<1> mark_to_clone;
    @field_list(1)
    bit<32> ingress_tstamp;
    @field_list(1)
    bit<32> egress_tstamp;
    @field_list(1)
    bit<24> deq_qdepth;
    @field_list(1)
    bit<24> enq_qdepth;
    @field_list(1)
    bit<32> flow_id;
    @field_list(1)
    bit<8> ttl;
}

#endif
