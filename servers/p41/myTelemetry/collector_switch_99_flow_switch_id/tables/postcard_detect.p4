#ifndef __POSTCARD_DETECT__
#define __POSTCARD_DETECT__


control PostcardDetect(
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata){

    action set_postcard_bit(){
        local_metadata.is_postcard = 1;
    }

    table table_detect_postcard{
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dst_port: exact;
        }
        actions = {
            NoAction;
            set_postcard_bit;
        }
    }

    action select_flow_register(bit<32> flow_reg_num){
        local_metadata.flow_register_number = flow_reg_num;
        local_metadata.flow_id = hdr.int_xd.seq_no;
    }

    action select_switch_register(bit<32> sw_reg_num ){
        local_metadata.switch_register_number = sw_reg_num;
        local_metadata.switch_id = hdr.int_xd.sw_id;
    }




    table table_detect_flow{
        key = {
            hdr.int_xd.seq_no: exact;  //using seq_no as a flow id
        }
        actions = {
            select_flow_register;
            NoAction;
        }
    }

    table table_detect_switch{
        key = {
            hdr.int_xd.sw_id: exact;
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
