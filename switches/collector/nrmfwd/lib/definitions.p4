#ifndef __TYPES__
#define __TYPES__

#define IP_VERSION_4 4w4
#define IP_PROTO_UDP 8w17
#define ETH_TYPE_IPV4 0x0800
#define IPV4_IHL_MIN 4w5


const bit<32> PACKET_AGGREGATOR_THRESHOLD = 1;


#define IS_I2E_CLONE(smeta) (smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)
#define IS_E2E_CLONE(smeta) (smeta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE)

#endif
