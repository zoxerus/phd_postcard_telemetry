#ifndef __HEADERS__
#define __HEADERS__

#include "definitions.p4"

/////// Ethernet Header ///////////
header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}
const bit<8> ETH_HEADER_LEN = 14;
// ############################ //

///// IPV4 Header ////////
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
//####################################//

//////  UDP Header /////////
header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_length;
    bit<16> checksum;
}
const bit<8> UDP_HEADER_LEN = 8;
//#############################//

const bit<3> NPROTO_ETHERNET = 0;

struct headers_t {
    // ethernet header
    ethernet_t ethernet;
    // IPV4 header
    ipv4_t ipv4;
    // UDP header
    udp_t udp;
}

struct local_metadata_t { /* Empyt Local Metadata */ }


#endif
