#ifndef __UTILS__
#define __UTILS__


// a function to help format the printout of standard_metadata
void print_standard(standard_metadata_t standard_metadata, string location ){
        log_msg(
                "\n {} standard_metadata: \
                    \n\t ingress_port:              {} \
                    \n\t egress_spec:               {} \
                    \n\t egress_port:               {} \
                    \n\t instance_type:             {} \
                    \n\t packet_length:             {} \
                    \n\t enq_timestamp:             {} \
                    \n\t enq_qdepth:                {} \
                    \n\t deq_timedelta:             {} \
                    \n\t deq_qdepth:                {} \
                    \n\t ingress_global_timestamp:  {} \
                    \n\t egress_global_timestamp:   {} \
                    \n\t mcast_grp:                 {} \
                    \n\t egress_rid:                {} \
                    \n\t checksum_error:            {} \
                    \n\t priority:                  {} ",
            {location,standard_metadata.ingress_port,
                standard_metadata.egress_spec,
                standard_metadata.egress_port,
                standard_metadata.instance_type,
                standard_metadata.packet_length,
                standard_metadata.enq_timestamp,
                standard_metadata.enq_qdepth,
                standard_metadata.deq_timedelta,
                standard_metadata.deq_qdepth,
                standard_metadata.ingress_global_timestamp,
                standard_metadata.egress_global_timestamp,
                standard_metadata.mcast_grp,
                standard_metadata.egress_rid,
                standard_metadata.checksum_error,
                standard_metadata.priority
            }
                );
            }

// a function to help format the printout of standard_metadata
action print_standardmeta(standard_metadata_t standard_metadata){
    log_msg(
            "\n standard_metadata: \
                \n\t ingress_port:              {} \
                \n\t egress_spec:               {} \
                \n\t egress_port:               {} \
                \n\t instance_type:             {} \
                \n\t packet_length:             {} \
                \n\t enq_timestamp:             {} \
                \n\t enq_qdepth:                {} \
                \n\t deq_timedelta:             {} \
                \n\t deq_qdepth:                {} \
                \n\t ingress_global_timestamp:  {} \
                \n\t egress_global_timestamp:   {} \
                \n\t mcast_grp:                 {} \
                \n\t egress_rid:                {} \
                \n\t checksum_error:            {} \
                \n\t priority:                  {} ",
        {standard_metadata.ingress_port,
            standard_metadata.egress_spec,
            standard_metadata.egress_port,
            standard_metadata.instance_type,
            standard_metadata.packet_length,
            standard_metadata.enq_timestamp,
            standard_metadata.enq_qdepth,
            standard_metadata.deq_timedelta,
            standard_metadata.deq_qdepth,
            standard_metadata.ingress_global_timestamp,
            standard_metadata.egress_global_timestamp,
            standard_metadata.mcast_grp,
            standard_metadata.egress_rid,
            standard_metadata.checksum_error,
            standard_metadata.priority
        }
            );
        }

#endif
