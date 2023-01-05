/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/


/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header mul_h {
    bit<16>     big;
    bit<16>     small;
    bit<32>     current_res;
    bit<16>     rest_coeff;
}
/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    mul_h        mul;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<16>     val1;
    bit<16>     val2;
    bit<16>     big;
    bit<16>     small;

}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init {
        meta.val1 = 0;
        meta.val2 = 0;
        meta.big = 0;
        meta.small = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(ig_intr_md.ingress_port){
            68:         parse_mul;
            default:    accept;
        }
    }

    state parse_mul {
        pkt.extract(hdr.mul);
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action mod_val(bit<16> val1,bit<16> val2) {
        meta.val1 = val1;
        meta.val2 = val2;
    }

    @stage(0)
    table mod_val_t {
        actions = {mod_val;}
        default_action = mod_val(0,0);
        size = 1;
    }

    action get_big_small() {
        meta.big = max(meta.val1,meta.val2);
        meta.small = min(meta.val1,meta.val2);
    }
    
    @stage(1)
    table get_big_small_t {
        actions = { get_big_small;}
        default_action = get_big_small();
        size = 1;
    }

    action add_mul_hdr() {
        hdr.mul.setValid();
        hdr.mul.big = meta.big;
        hdr.mul.small = meta.small;
        hdr.mul.current_res = 0;
        hdr.mul.rest_coeff = meta.small;
    }

    @stage(2)
    table add_mul_hdr_t {
        actions = { add_mul_hdr;}
        default_action = add_mul_hdr();
        size = 1;
    }

    action send() {
        ig_tm_md.ucast_egress_port = 0;
    }

    action recirc() {
        ig_tm_md.ucast_egress_port = 68;
    }

    @stage(5)
    table route_t {
        key = {
            hdr.mul.rest_coeff: exact;
        }
        actions = {send;recirc;}
        default_action = recirc();
        size = 4;
        const entries = {
            0:  send();
        }
    }

    Register<bit<32>,bit<1>>(1) cal_res;
    RegisterAction<bit<32>,bit<1>,bit<1>>(cal_res) _save_cal_res = {
        void apply(inout bit<32> reg_data){
            if(hdr.mul.rest_coeff == 0){
                reg_data = hdr.mul.current_res;
            }
        }
    };

    action save_cal_res() {
        _save_cal_res.execute(0);
    }

    @stage(8)
    table save_cal_res_t {
        actions = { save_cal_res;}
        default_action = save_cal_res();
        size = 1;
    }

    apply {
        if(ig_intr_md.ingress_port == 68){
        } else{
            mod_val_t.apply();          //stage 0
            get_big_small_t.apply();    //stage 1
            add_mul_hdr_t.apply();      //stage 2
        }
        route_t.apply();                // stage 5
        save_cal_res_t.apply();         // stage 8
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    mul_h        mul;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    bit<32> sum;
    bit<32> big;
    bit<32> tmp;
    bit<16> rest_coeff;
    bit<16> coeff;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition parse_mul;
    }

    state parse_mul {
        pkt.extract(hdr.mul);
        meta.sum = hdr.mul.current_res;
        meta.rest_coeff = hdr.mul.rest_coeff;
        meta.tmp = 0;
        meta.coeff = 0;
        meta.big = (bit<32>)hdr.mul.big;
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    action shift_0() {
        meta.tmp = meta.big;
        meta.coeff = 1;
    }

    action shift_1() {
        meta.tmp = meta.big << 1;
        meta.coeff = 2;
    }

    action shift_2() {
        meta.tmp = meta.big << 2;
        meta.coeff = 4;
    }

    action shift_3() {
        meta.tmp = meta.big << 3;
        meta.coeff = 8;
    }

    action shift_4() {
        meta.tmp = meta.big << 4;
        meta.coeff = 16;
    }

    action shift_5() {
        meta.tmp = meta.big << 5;
        meta.coeff = 32;
    }

    action shift_6() {
        meta.tmp = meta.big << 6;
        meta.coeff = 64;
    }

    action shift_7() {
        meta.tmp = meta.big << 7;
        meta.coeff = 128;
    }

    action shift_8() {
        meta.tmp = meta.big << 8;
        meta.coeff = 256;
    }

    action shift_9() {
        meta.tmp = meta.big << 9;
        meta.coeff = 512;
    }

    action shift_10() {
        meta.tmp = meta.big << 10;
        meta.coeff = 1024;
    }

    action shift_11() {
        meta.tmp = meta.big << 11;
        meta.coeff = 2048;
    }

    action shift_12() {
        meta.tmp = meta.big << 12;
        meta.coeff = 4096;
    }

    action shift_13() {
        meta.tmp = meta.big << 13;
        meta.coeff = 8192;
    }

    action shift_14() {
        meta.tmp = meta.big << 14;
        meta.coeff = 16384;
    }

    action shift_15() {
        meta.tmp = meta.big << 15;
        meta.coeff = 32768;
    }

    action silence() {
        meta.tmp = 0;
        meta.coeff = 0;
    }

    @stage(1)
    table shift_round1_t {
        key = {
            meta.rest_coeff: range;
        }
        actions = { 
            shift_0;
            shift_1;
            shift_2;
            shift_3;
            shift_4;
            shift_5;
            shift_6;
            shift_7;
            shift_8;
            shift_9;
            shift_10;
            shift_11;
            shift_12;
            shift_13;
            shift_14;
            shift_15;
            silence;
        }
        default_action = silence();
    }

    action summary() {
        meta.rest_coeff = meta.rest_coeff - meta.coeff;
        meta.sum = meta.sum + meta.tmp;
    }

    @stage(2)
    table summary1_t {
        actions = { summary;}
        default_action = summary();
        size = 1;
    } 

    @stage(3)
    table shift_round2_t {
        key = {
            meta.rest_coeff: range;
        }
        actions = { 
            shift_0;
            shift_1;
            shift_2;
            shift_3;
            shift_4;
            shift_5;
            shift_6;
            shift_7;
            shift_8;
            shift_9;
            shift_10;
            shift_11;
            shift_12;
            shift_13;
            shift_14;
            shift_15;
            silence;
        }
        default_action = silence();
    }
    
    @stage(4)
    table summary2_t {
        actions = { summary;}
        default_action = summary();
        size = 1;
    } 

    @stage(5)
    table shift_round3_t {
        key = {
            meta.rest_coeff: range;
        }
        actions = { 
            shift_0;
            shift_1;
            shift_2;
            shift_3;
            shift_4;
            shift_5;
            shift_6;
            shift_7;
            shift_8;
            shift_9;
            shift_10;
            shift_11;
            shift_12;
            shift_13;
            shift_14;
            shift_15;
            silence;
        }
        default_action = silence();
    }
    
    @stage(6)
    table summary3_t {
        actions = { summary;}
        default_action = summary();
        size = 1;
    } 

    @stage(7)
    table shift_round4_t {
        key = {
            meta.rest_coeff: range;
        }
        actions = { 
            shift_0;
            shift_1;
            shift_2;
            shift_3;
            shift_4;
            shift_5;
            shift_6;
            shift_7;
            shift_8;
            shift_9;
            shift_10;
            shift_11;
            shift_12;
            shift_13;
            shift_14;
            shift_15;
            silence;
        }
        default_action = silence();
    }
    
    @stage(8)
    table summary4_t {
        actions = { summary;}
        default_action = summary();
        size = 1;
    }

    @stage(9)
    table shift_round5_t {
        key = {
            meta.rest_coeff: range;
        }
        actions = { 
            shift_0;
            shift_1;
            shift_2;
            shift_3;
            shift_4;
            shift_5;
            shift_6;
            shift_7;
            shift_8;
            shift_9;
            shift_10;
            shift_11;
            shift_12;
            shift_13;
            shift_14;
            shift_15;
            silence;
        }
        default_action = silence();
    }
    
    @stage(10)
    table summary5_t {
        actions = { summary;}
        default_action = summary();
        size = 1;
    }

    action update_hdr() {
        hdr.mul.current_res = meta.sum;
        hdr.mul.rest_coeff = meta.rest_coeff;
    }

    @stage(11)
    table update_hdr_t {
        actions = { update_hdr;}
        default_action = update_hdr();
        size = 1;
    }

    //Owing to an unpredictable bug, we have to do so
    action adjust_for_robust() {
        meta.big = meta.big & 0x0000ffff;
    }

    @stage(0)
    table adjust_for_robust_t {
        actions = { adjust_for_robust;}
        default_action = adjust_for_robust();
        size = 1;
    }

    apply {
        if(eg_intr_md.egress_port == 68) {
            adjust_for_robust_t.apply();    // stage 0

            shift_round1_t.apply();         // stage 1
            summary1_t.apply();             // stage 2
            shift_round2_t.apply();         // stage 3
            summary2_t.apply();             // stage 4
            shift_round3_t.apply();         // stage 5
            summary3_t.apply();             // stage 6  
            shift_round4_t.apply();         // stage 7
            summary4_t.apply();             // stage 8 
            shift_round5_t.apply();         // stage 9
            summary5_t.apply();             // stage 10 

            update_hdr_t.apply();       // stage 11          
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
