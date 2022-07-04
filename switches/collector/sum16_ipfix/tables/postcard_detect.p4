#ifndef __POSTCARD_DETECT__
#define __POSTCARD_DETECT__



/*
This control contains three tables, first one is applied to detect whether the
packet is a postcard, if it is then a flag in local_metadata is set and two
other match tables are applyed consecutively to match the flow and switch IDs
and store these IDs in the relevant local_metadata variables.
*/

control PostcardDetect(
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata){

    // this action basically sets the is_postcard flag to denote that this
    // packet is a postcard, so it can go through the relevant processing later
    action set_postcard_bit(){
        local_metadata.is_postcard = 1;
    }

    // a packet is considered to contain a postcard when it's sent to a certain
    // IP address and a certain udp port number.
    table table_detect_postcard{
        key = {
            hdr.ipv4.dst_addr: exact;
            hdr.udp.dst_port: exact;
        }
        actions = {
            NoAction;
            set_postcard_bit;
        }
    }

    // TODO: write a description for this action
    action select_flow_register(bit<32> flow_reg_num){
        local_metadata.flow_register_number = flow_reg_num;
        local_metadata.flow_id = hdr.ipfix_postcard.record.flow_id;
        // log_msg("flow_id: {} set to register: {}", {hdr.postcard.flow_id, flow_reg_num});
    }

    // TODO: write a description
    action select_switch_register(bit<32> sw_reg_num ){
        local_metadata.switch_register_number = sw_reg_num;
        local_metadata.switch_id =
            hdr.ipfix_postcard.ipfix_header.observation_domain;
        // log_msg("sw_id: {} set to register: {}",{hdr.postcard.sw_id, sw_reg_num});
    }




    table table_detect_flow{
        key = {
            hdr.ipfix_postcard.record.flow_id: exact;
        }
        actions = {
            select_flow_register;
            NoAction;
        }
    }

    table table_detect_switch{
        key = {
            hdr.ipfix_postcard.ipfix_header.observation_domain: exact;
        }
        actions = {
            select_switch_register;
            NoAction;
        }
    }

    apply{

        if (table_detect_postcard.apply().hit){
            table_detect_flow.apply();
            table_detect_switch.apply();
        }
    }

}

#endif
