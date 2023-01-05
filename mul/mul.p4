/*
 * @Author: Shicong Chen
 * @Email: Sdotchen@163.com
 * @Version: 1.0
 */
/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

#define RECIRC_PORT 68

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
    bit<32>     big;
    bit<32>     small;
    bit<64>     current_res;
    bit<32>     rest_coeff;
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
    bit<32>     val1;
    bit<32>     val2;
    bit<32>     big;
    bit<32>     small;
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
            RECIRC_PORT:         parse_mul;
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
    action mod_val(bit<32> val1,bit<32> val2) {
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
        ig_tm_md.ucast_egress_port = RECIRC_PORT;
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

    Register<bit<32>,bit<1>>(1) cal_res_lo;
    RegisterAction<bit<32>,bit<1>,bit<1>>(cal_res_lo) _save_cal_res_lo = {
        void apply(inout bit<32> reg_data){
            if(hdr.mul.rest_coeff == 0){
                reg_data = hdr.mul.current_res[31:0];
            }
        }
    };

    action save_cal_res_lo() {
        _save_cal_res_lo.execute(0);
    }

    @stage(10)
    table save_cal_res_lo_t {
        actions = { save_cal_res_lo;}
        default_action = save_cal_res_lo();
        size = 1;
    }

    Register<bit<32>,bit<1>>(1) cal_res_hi;
    RegisterAction<bit<32>,bit<1>,bit<1>>(cal_res_hi) _save_cal_res_hi = {
        void apply(inout bit<32> reg_data){
            if(hdr.mul.rest_coeff == 0){
                reg_data = hdr.mul.current_res[63:32];
            }
        }
    };

    action save_cal_res_hi() {
        _save_cal_res_hi.execute(0);
    }

    @stage(11)
    table save_cal_res_hi_t {
        actions = { save_cal_res_hi;}
        default_action = save_cal_res_hi();
        size = 1;
    }

    apply {
        if(ig_intr_md.ingress_port == RECIRC_PORT){
        } else{
            mod_val_t.apply();          //stage 0
            get_big_small_t.apply();    //stage 1
            add_mul_hdr_t.apply();      //stage 2
        }
        route_t.apply();                // stage 5
        save_cal_res_lo_t.apply();         // stage 8
        save_cal_res_hi_t.apply();
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
    bit<64> sum;
    bit<64> tmp;
    bit<20> rest_coeff;
    bit<20> coeff;
    bit<12> huge_part;
    bit<64> tmp2;
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
        meta.rest_coeff = hdr.mul.rest_coeff[19:0];
        meta.tmp = 0;
        meta.coeff = 0;
        meta.huge_part = hdr.mul.rest_coeff[31:20];
        meta.tmp2 = 0;
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
    action huge_oper_1() {
        meta.huge_part = meta.huge_part - 1;
        meta.tmp2 = (hdr.mul.big >> 12) ++ (hdr.mul.big << 20);
    }

    action huge_oper_2() {
        meta.huge_part = meta.huge_part - 2;
        meta.tmp2 = (hdr.mul.big >> 11) ++ (hdr.mul.big << 21);
    }

    action huge_oper_3() {
        meta.huge_part = meta.huge_part - 4;
        meta.tmp2 = (hdr.mul.big >> 10) ++ (hdr.mul.big << 22);
    }

    action huge_oper_4() {
        meta.huge_part = meta.huge_part - 8;
        meta.tmp2 = (hdr.mul.big >> 9) ++ (hdr.mul.big << 23);
    }

    action huge_oper_5() {
        meta.huge_part = meta.huge_part - 16;
        meta.tmp2 = (hdr.mul.big >> 8) ++ (hdr.mul.big << 24);
    }

    action huge_oper_6() {
        meta.huge_part = meta.huge_part - 32;
        meta.tmp2 = (hdr.mul.big >> 7) ++ (hdr.mul.big << 25);
    }

    action huge_oper_7() {
        meta.huge_part = meta.huge_part - 64;
        meta.tmp2 = (hdr.mul.big >> 6) ++ (hdr.mul.big << 26);
    }

    action huge_oper_8() {
        meta.huge_part = meta.huge_part - 128;
        meta.tmp2 = (hdr.mul.big >> 5) ++ (hdr.mul.big << 27);
    }

    action huge_oper_9() {
        meta.huge_part = meta.huge_part - 256;
        meta.tmp2 = (hdr.mul.big >> 4) ++ (hdr.mul.big << 28);
    }

    action huge_oper_10() {
        meta.huge_part = meta.huge_part - 512;
        meta.tmp2 = (hdr.mul.big >> 3) ++ (hdr.mul.big << 29);
    }

    action huge_oper_11() {
        meta.huge_part = meta.huge_part - 1024;
        meta.tmp2 = (hdr.mul.big >> 2) ++ (hdr.mul.big << 30);
    }

    action huge_oper_12() {
        meta.huge_part = meta.huge_part - 2048;
        meta.tmp2 = (hdr.mul.big >> 1) ++ (hdr.mul.big << 31);
    }

    action huge_silence() {
        meta.tmp2 = 0;
    }

    @stage(1)
    table huge_oper_1_t {
        key = {
            meta.huge_part: range;
        }
        actions = {
            huge_oper_1;
            huge_oper_2;
            huge_oper_3;
            huge_oper_4;
            huge_oper_5;
            huge_oper_6;
            huge_oper_7;
            huge_oper_8;
            huge_oper_9;
            huge_oper_10;
            huge_oper_11;
            huge_oper_12;
            huge_silence;
        }
        default_action = huge_silence();
        const entries = {
            0..0:           huge_silence();
            1..1:           huge_oper_1();
            2..3:           huge_oper_2();
            4..7:           huge_oper_3();
            8..15:          huge_oper_4();
            16..31:         huge_oper_5();
            32..63:         huge_oper_6();
            64..127:        huge_oper_7();
            128..255:       huge_oper_8();
            256..511:       huge_oper_9();
            512..1023:      huge_oper_10();
            1024..2047:     huge_oper_11();
            2048..4095:     huge_oper_12();
        }
    }
    
    // used in stage 2 4 6 8 10
    action huge_add() {
        meta.sum = meta.sum + meta.tmp2;
    }

    @stage(2)
    table huge_add_1_t {
        actions = {huge_add;}
        default_action = huge_add();
        size = 1;
    }

    @stage(3)
    table huge_oper_2_t {
        key = {
            meta.huge_part: range;
        }
        actions = {
            huge_oper_1;
            huge_oper_2;
            huge_oper_3;
            huge_oper_4;
            huge_oper_5;
            huge_oper_6;
            huge_oper_7;
            huge_oper_8;
            huge_oper_9;
            huge_oper_10;
            huge_oper_11;
            huge_oper_12;
            huge_silence;
        }
        default_action = huge_silence();
        const entries = {
            0..0:           huge_silence();
            1..1:           huge_oper_1();
            2..3:           huge_oper_2();
            4..7:           huge_oper_3();
            8..15:          huge_oper_4();
            16..31:         huge_oper_5();
            32..63:         huge_oper_6();
            64..127:        huge_oper_7();
            128..255:       huge_oper_8();
            256..511:       huge_oper_9();
            512..1023:      huge_oper_10();
            1024..2047:     huge_oper_11();
            2048..4095:     huge_oper_12();
        }
    }

    @stage(4)
    table huge_add_2_t {
        actions = {huge_add;}
        default_action = huge_add();
        size = 1;
    }

    @stage(5)
    table huge_oper_3_t {
        key = {
            meta.huge_part: range;
        }
        actions = {
            huge_oper_1;
            huge_oper_2;
            huge_oper_3;
            huge_oper_4;
            huge_oper_5;
            huge_oper_6;
            huge_oper_7;
            huge_oper_8;
            huge_oper_9;
            huge_oper_10;
            huge_oper_11;
            huge_oper_12;
            huge_silence;
        }
        default_action = huge_silence();
        const entries = {
            0..0:           huge_silence();
            1..1:           huge_oper_1();
            2..3:           huge_oper_2();
            4..7:           huge_oper_3();
            8..15:          huge_oper_4();
            16..31:         huge_oper_5();
            32..63:         huge_oper_6();
            64..127:        huge_oper_7();
            128..255:       huge_oper_8();
            256..511:       huge_oper_9();
            512..1023:      huge_oper_10();
            1024..2047:     huge_oper_11();
            2048..4095:     huge_oper_12();
        }
    }

    @stage(6)
    table huge_add_3_t {
        actions = {huge_add;}
        default_action = huge_add();
        size = 1;
    }

    @stage(7)
    table huge_oper_4_t {
        key = {
            meta.huge_part: range;
        }
        actions = {
            huge_oper_1;
            huge_oper_2;
            huge_oper_3;
            huge_oper_4;
            huge_oper_5;
            huge_oper_6;
            huge_oper_7;
            huge_oper_8;
            huge_oper_9;
            huge_oper_10;
            huge_oper_11;
            huge_oper_12;
            huge_silence;
        }
        default_action = huge_silence();
        const entries = {
            0..0:           huge_silence();
            1..1:           huge_oper_1();
            2..3:           huge_oper_2();
            4..7:           huge_oper_3();
            8..15:          huge_oper_4();
            16..31:         huge_oper_5();
            32..63:         huge_oper_6();
            64..127:        huge_oper_7();
            128..255:       huge_oper_8();
            256..511:       huge_oper_9();
            512..1023:      huge_oper_10();
            1024..2047:     huge_oper_11();
            2048..4095:     huge_oper_12();
        }
    }

    @stage(8)
    table huge_add_4_t {
        actions = {huge_add;}
        default_action = huge_add();
        size = 1;
    }

    @stage(9)
    table huge_oper_5_t {
        key = {
            meta.huge_part: range;
        }
        actions = {
            huge_oper_1;
            huge_oper_2;
            huge_oper_3;
            huge_oper_4;
            huge_oper_5;
            huge_oper_6;
            huge_oper_7;
            huge_oper_8;
            huge_oper_9;
            huge_oper_10;
            huge_oper_11;
            huge_oper_12;
            huge_silence;
        }
        default_action = huge_silence();
        const entries = {
            0..0:           huge_silence();
            1..1:           huge_oper_1();
            2..3:           huge_oper_2();
            4..7:           huge_oper_3();
            8..15:          huge_oper_4();
            16..31:         huge_oper_5();
            32..63:         huge_oper_6();
            64..127:        huge_oper_7();
            128..255:       huge_oper_8();
            256..511:       huge_oper_9();
            512..1023:      huge_oper_10();
            1024..2047:     huge_oper_11();
            2048..4095:     huge_oper_12();
        }
    }

    @stage(10)
    table huge_add_5_t {
        actions = {huge_add;}
        default_action = huge_add();
        size = 1;
    }

    action shift_0() {
        meta.tmp = (bit<32>)0 ++ hdr.mul.big;
        meta.coeff = 1;
    }

    action shift_1() {
        meta.tmp[31:0] = hdr.mul.big << 1;
        meta.tmp[63:32] = hdr.mul.big >> 31;
        meta.coeff = 2;
    }

    action shift_2() {
        meta.tmp[31:0] = hdr.mul.big << 2;
        meta.tmp[63:32] = hdr.mul.big >> 30;
        meta.coeff = 4;
    }

    action shift_3() {
        meta.tmp[31:0] = hdr.mul.big << 3;
        meta.tmp[63:32] = hdr.mul.big >> 29;
        meta.coeff = 8;
    }

    action shift_4() {
        meta.tmp[31:0] = hdr.mul.big << 4;
        meta.tmp[63:32] = hdr.mul.big >> 28;
        meta.coeff = 16;
    }

    action shift_5() {
        meta.tmp[31:0] = hdr.mul.big << 5;
        meta.tmp[63:32] = hdr.mul.big >> 27;
        meta.coeff = 32;
    }

    action shift_6() {
        meta.tmp[31:0] = hdr.mul.big << 6;
        meta.tmp[63:32] = hdr.mul.big >> 26;
        meta.coeff = 64;
    }

    action shift_7() {
        meta.tmp[31:0] = hdr.mul.big << 7;
        meta.tmp[63:32] = hdr.mul.big >> 25;
        meta.coeff = 128;
    }

    action shift_8() {
        meta.tmp[31:0] = hdr.mul.big << 8;
        meta.tmp[63:32] = hdr.mul.big >> 24;
        meta.coeff = 256;
    }

    action shift_9() {
        meta.tmp[31:0] = hdr.mul.big << 9;
        meta.tmp[63:32] = hdr.mul.big >> 23;
        meta.coeff = 512;
    }

    action shift_10() {
        meta.tmp[31:0] = hdr.mul.big << 10;
        meta.tmp[63:32] = hdr.mul.big >> 22;
        meta.coeff = 1024;
    }

    action shift_11() {
        meta.tmp[31:0] = hdr.mul.big << 11;
        meta.tmp[63:32] = hdr.mul.big >> 21;
        meta.coeff = 2048;
    }

    action shift_12() {
        meta.tmp[31:0] = hdr.mul.big << 12;
        meta.tmp[63:32] = hdr.mul.big >> 20;
        meta.coeff = 4096;
    }

    action shift_13() {
        meta.tmp[31:0] = hdr.mul.big << 13;
        meta.tmp[63:32] = hdr.mul.big >> 19;
        meta.coeff = 8192;
    }

    action shift_14() {
        meta.tmp[31:0] = hdr.mul.big << 14;
        meta.tmp[63:32] = hdr.mul.big >> 18;
        meta.coeff = 16384;
    }

    action shift_15() {
        meta.tmp[31:0] = hdr.mul.big << 15;
        meta.tmp[63:32] = hdr.mul.big >> 17;
        meta.coeff = 32768;
    }

    action shift_16() {
        meta.tmp[31:0] = hdr.mul.big << 16;
        meta.tmp[63:32] = hdr.mul.big >> 16;
        meta.coeff = 65536;
    }

    action shift_17() {
        meta.tmp[31:0] = hdr.mul.big << 17;
        meta.tmp[63:32] = hdr.mul.big >> 15;
        meta.coeff = 131072;
    }

    action shift_18() {
        meta.tmp[31:0] = hdr.mul.big << 18;
        meta.tmp[63:32] = hdr.mul.big >> 14;
        meta.coeff = 262144;
    }

    action shift_19() {
        meta.tmp[31:0] = hdr.mul.big << 19;
        meta.tmp[63:32] = hdr.mul.big >> 13;
        meta.coeff = 524288;
    }

    action silence() {
        meta.tmp = 0;
        meta.coeff = 0;
    }

    @stage(0)
    table shift_round1_t {
        key = {
            meta.rest_coeff: range;
            meta.huge_part: exact;
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
            shift_16;
            shift_17;
            shift_18;
            shift_19;
            silence;
        }
        default_action = silence();
        const entries = {
            (0..0,0):               silence();
            (1..1,0):               shift_0();
            (2..3,0):               shift_1();
            (4..7,0):               shift_2();
            (8..15,0):              shift_3();
            (16..31,0):             shift_4();
            (32..63,0):             shift_5();
            (64..127,0):            shift_6();
            (128..255,0):           shift_7();
            (256..511,0):           shift_8();
            (512..1023,0):          shift_9();
            (1024..2047,0):         shift_10();
            (2048..4095,0):         shift_11();
            (4096..8191,0):         shift_12();
            (8192..16383,0):        shift_13();
            (16384..32767,0):       shift_14();
            (32768..65535,0):       shift_15();
            (65536..131071,0):      shift_16();
            (131072..262143,0):     shift_17();
            (262144..524287,0):     shift_18();
            (524288..1048575,0):    shift_19();
        }
    }

    action summary() {
        meta.rest_coeff = meta.rest_coeff - meta.coeff;
        meta.sum = meta.sum + meta.tmp;
    }

    @stage(1)
    table summary1_t {
        actions = { summary;}
        default_action = summary();
        size = 1;
    } 

    @stage(2)
    table shift_round2_t {
        key = {
            meta.rest_coeff: range;
            meta.huge_part: exact;
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
            shift_16;
            shift_17;
            shift_18;
            shift_19;
            silence;
        }
        default_action = silence();
        const entries = {
            (0..0,0):               silence();
            (1..1,0):               shift_0();
            (2..3,0):               shift_1();
            (4..7,0):               shift_2();
            (8..15,0):              shift_3();
            (16..31,0):             shift_4();
            (32..63,0):             shift_5();
            (64..127,0):            shift_6();
            (128..255,0):           shift_7();
            (256..511,0):           shift_8();
            (512..1023,0):          shift_9();
            (1024..2047,0):         shift_10();
            (2048..4095,0):         shift_11();
            (4096..8191,0):         shift_12();
            (8192..16383,0):        shift_13();
            (16384..32767,0):       shift_14();
            (32768..65535,0):       shift_15();
            (65536..131071,0):      shift_16();
            (131072..262143,0):     shift_17();
            (262144..524287,0):     shift_18();
            (524288..1048575,0):    shift_19();
        }
    }
    
    @stage(3)
    table summary2_t {
        actions = { summary;}
        default_action = summary();
        size = 1;
    } 

    @stage(4)
    table shift_round3_t {
        key = {
            meta.rest_coeff: range;
            meta.huge_part: exact;
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
            shift_16;
            shift_17;
            shift_18;
            shift_19;
            silence;
        }
        default_action = silence();
        const entries = {
            (0..0,0):               silence();
            (1..1,0):               shift_0();
            (2..3,0):               shift_1();
            (4..7,0):               shift_2();
            (8..15,0):              shift_3();
            (16..31,0):             shift_4();
            (32..63,0):             shift_5();
            (64..127,0):            shift_6();
            (128..255,0):           shift_7();
            (256..511,0):           shift_8();
            (512..1023,0):          shift_9();
            (1024..2047,0):         shift_10();
            (2048..4095,0):         shift_11();
            (4096..8191,0):         shift_12();
            (8192..16383,0):        shift_13();
            (16384..32767,0):       shift_14();
            (32768..65535,0):       shift_15();
            (65536..131071,0):      shift_16();
            (131072..262143,0):     shift_17();
            (262144..524287,0):     shift_18();
            (524288..1048575,0):    shift_19();
        }
    }
    
    @stage(5)
    table summary3_t {
        actions = { summary;}
        default_action = summary();
        size = 1;
    } 

    @stage(6)
    table shift_round4_t {
        key = {
            meta.rest_coeff: range;
            meta.huge_part: exact;
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
            shift_16;
            shift_17;
            shift_18;
            shift_19;
            silence;
        }
        default_action = silence();
        const entries = {
            (0..0,0):               silence();
            (1..1,0):               shift_0();
            (2..3,0):               shift_1();
            (4..7,0):               shift_2();
            (8..15,0):              shift_3();
            (16..31,0):             shift_4();
            (32..63,0):             shift_5();
            (64..127,0):            shift_6();
            (128..255,0):           shift_7();
            (256..511,0):           shift_8();
            (512..1023,0):          shift_9();
            (1024..2047,0):         shift_10();
            (2048..4095,0):         shift_11();
            (4096..8191,0):         shift_12();
            (8192..16383,0):        shift_13();
            (16384..32767,0):       shift_14();
            (32768..65535,0):       shift_15();
            (65536..131071,0):      shift_16();
            (131072..262143,0):     shift_17();
            (262144..524287,0):     shift_18();
            (524288..1048575,0):    shift_19();
        }
    }
    
    @stage(7)
    table summary4_t {
        actions = { summary;}
        default_action = summary();
        size = 1;
    }

    @stage(8)
    table shift_round5_t {
        key = {
            meta.rest_coeff: range;
            meta.huge_part: exact;
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
            shift_16;
            shift_17;
            shift_18;
            shift_19;
            silence;
        }
        default_action = silence();
        const entries = {
            (0..0,0):               silence();
            (1..1,0):               shift_0();
            (2..3,0):               shift_1();
            (4..7,0):               shift_2();
            (8..15,0):              shift_3();
            (16..31,0):             shift_4();
            (32..63,0):             shift_5();
            (64..127,0):            shift_6();
            (128..255,0):           shift_7();
            (256..511,0):           shift_8();
            (512..1023,0):          shift_9();
            (1024..2047,0):         shift_10();
            (2048..4095,0):         shift_11();
            (4096..8191,0):         shift_12();
            (8192..16383,0):        shift_13();
            (16384..32767,0):       shift_14();
            (32768..65535,0):       shift_15();
            (65536..131071,0):      shift_16();
            (131072..262143,0):     shift_17();
            (262144..524287,0):     shift_18();
            (524288..1048575,0):    shift_19();
        }
    }
    
    @stage(9)
    table summary5_t {
        actions = { summary;}
        default_action = summary();
        size = 1;
    }


    action update_hdr() {
        hdr.mul.current_res = meta.sum;
        hdr.mul.rest_coeff = meta.huge_part ++ meta.rest_coeff;
    }

    @stage(11)
    table update_hdr_t {
        actions = { update_hdr;}
        default_action = update_hdr();
        size = 1;
    }

    apply {
        if(eg_intr_md.egress_port == RECIRC_PORT) {
            shift_round1_t.apply();         // light / stage 0
            huge_oper_1_t.apply();          // huge / stage 1   
            summary1_t.apply();             // light / stage 1
            huge_add_1_t.apply();           // huge / stage 2

            shift_round2_t.apply();         // light / stage 2
            huge_oper_2_t.apply();          // huge / stage 3
            summary2_t.apply();             // light / stage 3
            huge_add_2_t.apply();           // huge / stage 4

            shift_round3_t.apply();         // light / stage 4
            huge_oper_3_t.apply();          // huge / stage 5
            summary3_t.apply();             // light / stage 5
            huge_add_3_t.apply();           // huge / stage 6

            shift_round4_t.apply();         // light / stage 6
            huge_oper_4_t.apply();          // huge / stage 7
            summary4_t.apply();             // light / stage 7
            huge_add_4_t.apply();           // huge / stage 8
            
            shift_round5_t.apply();         // light / stage 8
            huge_oper_5_t.apply();          // huge / stage 9
            summary5_t.apply();             // light / stage 9
            huge_add_5_t.apply();           // huge / stage 10

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
