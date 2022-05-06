#ifndef __POSTCARD_DETECT__
#define __POSTCARD_DETECT__


control PostcardDetect(
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata){

    action set_postcard_bit(){
        local_metadata.is_postcard = 1;
        log_msg("postcard detected from: {}", {hdr.postcard.sw_id});
    }

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

    action select_flow_register(bit<32> flow_reg_num){
        local_metadata.flow_register_number = flow_reg_num;
        local_metadata.flow_id = hdr.postcard.flow_id;
        log_msg("flow_id: {} set to register: {}", {hdr.postcard.flow_id, flow_reg_num});
    }

    action select_switch_register(bit<32> sw_reg_num ){
        local_metadata.switch_register_number = sw_reg_num;
        local_metadata.switch_id = hdr.postcard.sw_id;
        log_msg("sw_id: {} set to register: {}",{hdr.postcard.sw_id, sw_reg_num});
    }




    table table_detect_flow{
        key = {
            hdr.postcard.flow_id: exact;  
        }
        actions = {
            select_flow_register;
            NoAction;
        }
    }

    table table_detect_switch{
        key = {
            hdr.postcard.sw_id: exact;
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
