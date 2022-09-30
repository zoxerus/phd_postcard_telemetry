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


// the main header of an IPFIX message
header group_header_t{
    bit<4> version;
    bit<6> hw_id;
    bit<22> sequence_number;
    bit<32> node_id;
}

// the data record of the incoming postcard, this data is extracted and then
// summerized in a new IPFIX message using the data_sum_t struct.
header report_header_t {
    bit<4> reptype;
    bit<4> intype;
    bit<8> report_length;
    bit<8> md_length;
    bit<1> dropped;
    bit<1> cqa; //congested queue association
    bit<1> tfa; //tracked flow association
    bit<1> i_rep; //intermediate report
    bit<4> rsvd;
    bit<16> md_bits;
    bit<16> ds_id;
    bit<16> ds_bits;
    bit<16> ds_status;
    bit<16> l1_in_id;
    bit<16> l1_out_id;
    bit<32> latency;
    bit<8> qoc_id;
    bit<24> q_occupancy;
    bit<64> ingress_tstamp;
    bit<64> egress_tstamp;
    bit<32> l2_in_id;
    bit<32> l2_out_id;
    bit<32> egress_tx_use;
    bit<8> buffer_id;
    bit<24> buffer_occupancy;
    bit<8> qdr_id;
    bit<8> drop_reason;
    bit<16> padding;
}
#define GROUP_LENGTH 8
#define REPORT_LENGTH 60
#define REPORT_LEN_BITS 480

struct headers_t {
    ethernet_t xd_ethernet;
    ipv4_t xd_ipv4;
    udp_t xd_udp;

    group_header_t group_header;
    report_header_t report;

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
    bit<22> seq_num;
}

#endif
