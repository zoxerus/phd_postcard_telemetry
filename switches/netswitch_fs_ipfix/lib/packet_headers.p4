#ifndef __HEADERS__
#define __HEADERS__

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

struct ipfix_header_t{
    bit<16> version_number;
    bit<16> message_length;
    bit<32> export_time;
    bit<32> sequence_number;
    bit<32> observation_domain;
}

struct data_set_t {
    bit<16> set_id;
    bit<16> set_length;
}

struct data_record_t {
    bit<32> flow_id;
    bit<8>  ttl;
    bit<48> ingress_tstamp;
    bit<48> egress_tstamp;
    bit<24> deq_depth;
    bit<24> enq_depth;
    bit<16> ingress_interface;
    bit<16> egress_interface;
}
#define DATA_RECORD_ID 256

header ipfix_message_t {
    ipfix_header_t msg;
    data_set_t     set;
    data_record_t  record;
}
#define SET_LEN 31
#define IPFIX_LEN 47

struct headers_t {
    ethernet_t xd_ethernet;
    ipv4_t xd_ipv4;
    udp_t xd_udp;

    ipfix_message_t ipfix;

    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
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
    bit<9> ingress_interface;
    @field_list(1)
    bit<9> egress_interface;
    @field_list(1)
    bit<32> seq_num;
}

#endif
