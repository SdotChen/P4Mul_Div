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

/* Normally, setting ENABLE_AGAIN 1 will half the times of recirculation. */

#define ENABLE_AGAIN 1

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

/* A self-define header for division calculation. */
header div_h {
    bit<32> dividend;
    bit<32> divisor;
    bit<32> quotient;
    bit<32> remainder;
    bit<8>  isDone;
    bit<16> seq;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    div_h        div;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<32>     dividend;
    bit<32>     divisor;
    bit<32>     diff;
    bit<2>      res1;
    bit<2>      res2;
    bit<16>     seq;
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
        meta.dividend = 0;
        meta.divisor = 0;      
        meta.diff = 0; 
        meta.res1 = 0;
        meta.res2 = 0;
        meta.seq = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(ig_intr_md.ingress_port){
            RECIRC_PORT:         parse_div;
            default:    accept;
        }
    }

    state parse_div {
        pkt.extract(hdr.div);
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
    
    Random<bit<32>>() rnd1;
    Random<bit<32>>() rnd2;

    action get_rnd_dividend() {
        meta.dividend = rnd1.get();
    }

    table get_rnd_dividend_t {
        actions = { get_rnd_dividend;}
        default_action = get_rnd_dividend();
        size = 1;
    }

    action get_rnd_divisor() {
        meta.divisor = rnd2.get();
    }

    @stage(0)
    table get_rnd_divisor_t {
        actions = { get_rnd_divisor;}
        default_action = get_rnd_divisor();
        size = 1;
    }

    // action mod_val(bit<32> dividend,bit<32> divisor) {
    //     meta.dividend = dividend;
    //     meta.divisor = divisor;
    // }

    // @stage(0)
    // table mod_val_t {
    //     actions = {mod_val;}
    //     default_action = mod_val(0,0);
    //     size = 1;
    // }

    Register<bit<16>,bit<1>>(1) seq;
    RegisterAction<bit<16>,bit<1>,bit<16>>(seq) _get_seq = {
        void apply(inout bit<16> reg_data, out bit<16> result) {
            result = reg_data;
            reg_data = reg_data + 1;
        }
    };

    action get_seq() {
        meta.seq = _get_seq.execute(0);
    }

    @stage(0)
    table get_seq_t {
        actions = { get_seq;}
        default_action = get_seq();
        size = 1;
    }

    Register<bit<32>,bit<16>>(65536) dividend;
    RegisterAction<bit<32>,bit<16>,bit<1>>(dividend) _save_dividend = {
        void apply(inout bit<32> reg_data) {
            reg_data = meta.dividend;
        }
    };

    action save_dividend() {
        _save_dividend.execute(meta.seq);
    }

    @stage(5)
    table save_dividend_t {
        actions = { save_dividend;}
        default_action = save_dividend();
    }

    Register<bit<32>,bit<16>>(65536) divisor;
    RegisterAction<bit<32>,bit<16>,bit<1>>(divisor) _save_divisor = {
        void apply(inout bit<32> reg_data) {
            reg_data = meta.divisor;
        }
    };

    action save_divisor() {
        _save_divisor.execute(meta.seq);
    }

    @stage(5)
    table save_divisor_t {
        actions = { save_divisor;}
        default_action = save_divisor();
        size = 1;
    }

    action add_div_hdr() {
        hdr.div.setValid();
        hdr.div.dividend = meta.dividend;
        hdr.div.divisor = meta.divisor;
        hdr.div.quotient = 0;
        hdr.div.remainder = 0;
        hdr.div.isDone = 0;
        hdr.div.seq = meta.seq;
        meta.diff = meta.dividend - meta.divisor;
    }

    @stage(1)
    table add_div_hdr_t {
        actions = {add_div_hdr;}
        default_action = add_div_hdr();
        size = 1;
    }

    action dividend_0() {
        hdr.div.quotient = 0;
        hdr.div.remainder = 0;
        hdr.div.isDone = 1;
    }

    @stage(3)
    table dividend_0_t {
        actions = { dividend_0;}
        default_action = dividend_0();
        size = 1;
    }

    action divisor_1() {
        hdr.div.quotient = hdr.div.dividend;
        hdr.div.remainder = 0;
        hdr.div.isDone = 1;
    }

    @stage(4)
    table divisor_1_t {
        actions = { divisor_1;}
        default_action = divisor_1();
        size = 1;
    }

    action same() {
        hdr.div.quotient = 1;
        hdr.div.remainder = 0;
        hdr.div.isDone = 1;
    }

    @stage(3)
    table same_t {
        actions = { same;}
        default_action = same();
        size = 1;
    }

    // error situation
    action divisor_0() {
        hdr.div.quotient = 4294967295; // 2^32 - 1
        hdr.div.remainder = 4294967295;
        hdr.div.isDone = 2;
    }

    @stage(4)
    table divisor_0_t {
        actions = { divisor_0;}
        default_action = divisor_0();
        size = 1;
    }

    Register<bit<32>,bit<1>>(1) special_1;
    RegisterAction<bit<32>,bit<1>,bit<2>>(special_1) _check_dividend = {
        void apply(inout bit<32> reg_data, out bit<2> result) {
            reg_data = 0;
            if(hdr.div.dividend == 0) {
                result = 1;
            } else if(meta.diff == 0) {
                result = 2;
            } else {
                result = 0;
            }
        }
    };

    action check_dividend() {
        meta.res1 = _check_dividend.execute(0);
    }

    @stage(2)
    table check_dividend_t {
        actions = { check_dividend;}
        default_action = check_dividend();
        size = 1;
    }

    Register<bit<32>,bit<1>>(1) special_2;
    RegisterAction<bit<32>,bit<1>,bit<2>>(special_2) _check_divisor = {
        void apply(inout bit<32> reg_data, out bit<2> result) {
            reg_data = 0;
            if(hdr.div.divisor == 0) {
                result = 2;
            } else if(hdr.div.divisor == 1) {
                result = 1;
            } else {
                result = 0;
            }
        }
    };

    action check_divisor() {
        meta.res2 = _check_divisor.execute(0);
    }

    @stage(2)
    table check_divisor_t {
        actions = { check_divisor;}
        default_action = check_divisor();
        size = 1;
    }

    Register<bit<32>,bit<16>>(65536) reg_quotient;
    RegisterAction<bit<32>,bit<16>,bit<1>>(reg_quotient) _save_quotient = {
        void apply(inout bit<32> reg_data) {
            reg_data = hdr.div.quotient;
        }
    };

    action save_quotient() {
        _save_quotient.execute(hdr.div.seq);
    }

    @stage(7)
    table save_quotient_t {
        actions = { save_quotient;}
        default_action = save_quotient();
        size = 1;
    }

    Register<bit<32>,bit<16>>(65536) reg_remainder;
    RegisterAction<bit<32>,bit<16>,bit<1>>(reg_remainder) _save_remainder = {
        void apply(inout bit<32> reg_data) {
            reg_data = hdr.div.remainder;
        }
    };

    action save_remainder() {
        _save_remainder.execute(hdr.div.seq);
    }

    @stage(7)
    table save_remainder_t {
        actions = { save_remainder;}
        default_action = save_remainder();
        size = 1;
    }

    // set a port for forwarding
    action send() {
        ig_tm_md.ucast_egress_port = 0;
    }

    action recirc() {
        ig_tm_md.ucast_egress_port = RECIRC_PORT;
    }

    // can be extended to an IPv4 table
    @stage(10)
    table send_t {
        actions = { send;}
        default_action = send();
        size = 1;
    }

    @stage(10)
    table recirc_t {
        actions = { recirc;}
        default_action = recirc();
        size = 1;
    }

    

    apply {
        if(ig_intr_md.ingress_port != RECIRC_PORT){
            // mod_val_t.apply();          // stage 0
            get_rnd_dividend_t.apply(); // stage 0
            get_rnd_divisor_t.apply();  // stage 0

            get_seq_t.apply();          // stage 0

            
            add_div_hdr_t.apply();      // stage 1

            
            /* processing of special situations for avoiding unnecessary recirculations */

            check_dividend_t.apply();   // stage 2
            check_divisor_t.apply();    // stage 2

            if(meta.res1 == 1) {
                dividend_0_t.apply();   // stage 3
            } else if(meta.res1 == 2) {
                same_t.apply();         // stage 3
            }

            if(meta.res2 == 1) {
                divisor_1_t.apply();    // stage 4
            } else if(meta.res2 == 2) {
                divisor_0_t.apply();    // stage 4
            }

            save_dividend_t.apply();    // stage 5
            save_divisor_t.apply();     // stage 5
        }
        
        /* Calculation finished */
        if(hdr.div.isDone != 0) {    
            save_quotient_t.apply();    // stage 7
            save_remainder_t.apply();   // stage 7
            send_t.apply();             // stage 10
        } else {
            recirc_t.apply();           // stage 10
        }

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
    div_h        div;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    bit<16> divisor_hi;
    bit<16> divisor_lo;
    bit<16> dividend_hi;
    bit<16> dividend_lo;
    bit<8>  exp_dividend;
    bit<8>  exp_divisor;
    bit<8>  delta_exp;
    bit<8>  delta_exp_sat;
    bit<32> shifted_divisor;
    bit<32> delta_val;
    bit<32> delta_val_sat;
    bit<1>  res1;
    bit<1>  res2;
    bit<1>  res3;
    bit<1>  res4;
    bit<1>  res5;
    bit<1>  res6;
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
    div_h   div;

    state start {
        pkt.extract(eg_intr_md);
        transition meta_init;
    }

    state meta_init {
        meta.divisor_hi = 0;
        meta.divisor_lo = 0;
        meta.dividend_hi = 0;
        meta.dividend_lo = 0;
        meta.exp_dividend = 0;
        meta.exp_divisor = 0;
        meta.delta_exp = 0;
        meta.delta_exp_sat = 0;
        meta.shifted_divisor = 0;
        meta.delta_val = 0;
        meta.delta_val_sat = 0;
        meta.res1 = 0;
        meta.res2 = 0;
        meta.res3 = 0;
        meta.res4 = 0;
        meta.res5 = 0;
        meta.res6 = 0;

        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(eg_intr_md.egress_port) {
            RECIRC_PORT:         parse_div;
            default:    delete_div;
        }
    }

    state delete_div {
        pkt.extract(div);
        transition accept;
    }

    state parse_div {
        pkt.extract(hdr.div);

        meta.divisor_hi = hdr.div.divisor[31:16];
        meta.divisor_lo = hdr.div.divisor[15:0];
        meta.dividend_hi = hdr.div.dividend[31:16];
        meta.dividend_lo = hdr.div.dividend[15:0];

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

    action set_dividend_exp_31() {
        meta.exp_dividend = 31;
    }

    action set_dividend_exp_30() {
        meta.exp_dividend = 30;
    }

    action set_dividend_exp_29() {
        meta.exp_dividend = 29;
    }

    action set_dividend_exp_28() {
        meta.exp_dividend = 28;
    }
    
    action set_dividend_exp_27() {
        meta.exp_dividend = 27;
    }
    
    action set_dividend_exp_26() {
        meta.exp_dividend = 26;
    }
    
    action set_dividend_exp_25() {
        meta.exp_dividend = 25;
    }
    
    action set_dividend_exp_24() {
        meta.exp_dividend = 24;
    }
    
    action set_dividend_exp_23() {
        meta.exp_dividend = 23;
    }
    
    action set_dividend_exp_22() {
        meta.exp_dividend = 22;
    }
    
    action set_dividend_exp_21() {
        meta.exp_dividend = 21;
    }
    
    action set_dividend_exp_20() {
        meta.exp_dividend = 20;
    }
    
    action set_dividend_exp_19() {
        meta.exp_dividend = 19;
    }
    
    action set_dividend_exp_18() {
        meta.exp_dividend = 18;
    }
    
    action set_dividend_exp_17() {
        meta.exp_dividend = 17;
    }
    
    action set_dividend_exp_16() {
        meta.exp_dividend = 16;
    }
    
    action set_dividend_exp_15() {
        meta.exp_dividend = 15;
    }
    
    action set_dividend_exp_14() {
        meta.exp_dividend = 14;
    }
    
    action set_dividend_exp_13() {
        meta.exp_dividend = 13;
    }
    
    action set_dividend_exp_12() {
        meta.exp_dividend = 12;
    }
    
    action set_dividend_exp_11() {
        meta.exp_dividend = 11;
    }
    
    action set_dividend_exp_10() {
        meta.exp_dividend = 10;
    }
    
    action set_dividend_exp_9() {
        meta.exp_dividend = 9;
    }
    
    action set_dividend_exp_8() {
        meta.exp_dividend = 8;
    }
    
    action set_dividend_exp_7() {
        meta.exp_dividend = 7;
    }
    
    action set_dividend_exp_6() {
        meta.exp_dividend = 6;
    }
    
    action set_dividend_exp_5() {
        meta.exp_dividend = 5;
    }
    
    action set_dividend_exp_4() {
        meta.exp_dividend = 4;
    }
    
    action set_dividend_exp_3() {
        meta.exp_dividend = 3;
    }
    
    action set_dividend_exp_2() {
        meta.exp_dividend = 2;
    }
    
    action set_dividend_exp_1() {
        meta.exp_dividend = 1;
    }
    
    action set_dividend_exp_0() {
        meta.exp_dividend = 0;
    }
   
    action set_divisor_exp_32() {
        meta.exp_divisor = 32;
    }
 
    action set_divisor_exp_31() {
        meta.exp_divisor = 31;
    }

    action set_divisor_exp_30() {
        meta.exp_divisor = 30;
    }

    action set_divisor_exp_29() {
        meta.exp_divisor = 29;
    }

    action set_divisor_exp_28() {
        meta.exp_divisor = 28;
    }
    
    action set_divisor_exp_27() {
        meta.exp_divisor = 27;
    }
    
    action set_divisor_exp_26() {
        meta.exp_divisor = 26;
    }
    
    action set_divisor_exp_25() {
        meta.exp_divisor = 25;
    }
    
    action set_divisor_exp_24() {
        meta.exp_divisor = 24;
    }
    
    action set_divisor_exp_23() {
        meta.exp_divisor = 23;
    }
    
    action set_divisor_exp_22() {
        meta.exp_divisor = 22;
    }
    
    action set_divisor_exp_21() {
        meta.exp_divisor = 21;
    }
    
    action set_divisor_exp_20() {
        meta.exp_divisor = 20;
    }
    
    action set_divisor_exp_19() {
        meta.exp_divisor = 19;
    }
    
    action set_divisor_exp_18() {
        meta.exp_divisor = 18;
    }
    
    action set_divisor_exp_17() {
        meta.exp_divisor = 17;
    }
    
    action set_divisor_exp_16() {
        meta.exp_divisor = 16;
    }
    
    action set_divisor_exp_15() {
        meta.exp_divisor = 15;
    }
    
    action set_divisor_exp_14() {
        meta.exp_divisor = 14;
    }
    
    action set_divisor_exp_13() {
        meta.exp_divisor = 13;
    }
    
    action set_divisor_exp_12() {
        meta.exp_divisor = 12;
    }
    
    action set_divisor_exp_11() {
        meta.exp_divisor = 11;
    }
    
    action set_divisor_exp_10() {
        meta.exp_divisor = 10;
    }
    
    action set_divisor_exp_9() {
        meta.exp_divisor = 9;
    }
    
    action set_divisor_exp_8() {
        meta.exp_divisor = 8;
    }
    
    action set_divisor_exp_7() {
        meta.exp_divisor = 7;
    }
    
    action set_divisor_exp_6() {
        meta.exp_divisor = 6;
    }
    
    action set_divisor_exp_5() {
        meta.exp_divisor = 5;
    }
    
    action set_divisor_exp_4() {
        meta.exp_divisor = 4;
    }
    
    action set_divisor_exp_3() {
        meta.exp_divisor = 3;
    }
    
    action set_divisor_exp_2() {
        meta.exp_divisor = 2;
    }

    /* To be done only once in Egress for every packet */
    @stage(0)
    table set_divisor_t {
        key = {
            meta.divisor_hi:   range;
            meta.divisor_lo:   range;
        }
        actions = {
            set_divisor_exp_32;
            set_divisor_exp_31; // 2^30 ~ (2^31 -1)
            set_divisor_exp_30;
            set_divisor_exp_29;
            set_divisor_exp_28; 
            set_divisor_exp_27;
            set_divisor_exp_26; 
            set_divisor_exp_25;
            set_divisor_exp_24; 
            set_divisor_exp_23;
            set_divisor_exp_22; 
            set_divisor_exp_21;
            set_divisor_exp_20; 
            set_divisor_exp_19;
            set_divisor_exp_18; 
            set_divisor_exp_17; // 65536~131071
            set_divisor_exp_16; 
            set_divisor_exp_15;
            set_divisor_exp_14; 
            set_divisor_exp_13;
            set_divisor_exp_12; 
            set_divisor_exp_11;
            set_divisor_exp_10; 
            set_divisor_exp_9;
            set_divisor_exp_8; 
            set_divisor_exp_7;
            set_divisor_exp_6; 
            set_divisor_exp_5;
            set_divisor_exp_4; 
            set_divisor_exp_3; // 4~7
            set_divisor_exp_2; // 2~3
        }
        const entries = {
            (0..0,2..3):            set_divisor_exp_2();
            (0..0,4..7):            set_divisor_exp_3();
            (0..0,8..15):           set_divisor_exp_4();
            (0..0,16..31):          set_divisor_exp_5();
            (0..0,32..63):          set_divisor_exp_6();
            (0..0,64..127):         set_divisor_exp_7();
            (0..0,128..255):        set_divisor_exp_8();
            (0..0,256..511):        set_divisor_exp_9();
            (0..0,512..1023):       set_divisor_exp_10();
            (0..0,1024..2047):      set_divisor_exp_11();
            (0..0,2048..4095):      set_divisor_exp_12();
            (0..0,4096..8191):      set_divisor_exp_13();
            (0..0,8192..16383):     set_divisor_exp_14();
            (0..0,16384..32767):    set_divisor_exp_15();
            (0..0,32768..65535):    set_divisor_exp_16();
            (1..1,_):               set_divisor_exp_17();
            (2..3,_):               set_divisor_exp_18();
            (4..7,_):               set_divisor_exp_19();
            (8..15,_):              set_divisor_exp_20();
            (16..31,_):             set_divisor_exp_21();
            (32..63,_):             set_divisor_exp_22();
            (64..127,_):            set_divisor_exp_23();
            (128..255,_):           set_divisor_exp_24();
            (256..511,_):           set_divisor_exp_25();
            (512..1023,_):          set_divisor_exp_26();
            (1024..2047,_):         set_divisor_exp_27();
            (2048..4095,_):         set_divisor_exp_28();
            (4096..8191,_):         set_divisor_exp_29();
            (8192..16383,_):        set_divisor_exp_30();
            (16384..32767,_):       set_divisor_exp_31();
            (32768..65535,_):       set_divisor_exp_32();
        }
    }

    @stage(0)
    table set_dividend_t {
        key = {
            meta.dividend_hi:   range;
            meta.dividend_lo:   range;
        }
        actions = {
            set_dividend_exp_31; 
            set_dividend_exp_30;
            set_dividend_exp_29; 
            set_dividend_exp_28;
            set_dividend_exp_27; 
            set_dividend_exp_26;
            set_dividend_exp_25; 
            set_dividend_exp_24;
            set_dividend_exp_23; 
            set_dividend_exp_22;
            set_dividend_exp_21; 
            set_dividend_exp_20;
            set_dividend_exp_19; 
            set_dividend_exp_18;
            set_dividend_exp_17; 
            set_dividend_exp_16;
            set_dividend_exp_15; 
            set_dividend_exp_14;
            set_dividend_exp_13; 
            set_dividend_exp_12;
            set_dividend_exp_11; 
            set_dividend_exp_10;
            set_dividend_exp_9; 
            set_dividend_exp_8;
            set_dividend_exp_7; 
            set_dividend_exp_6;
            set_dividend_exp_5; 
            set_dividend_exp_4;
            set_dividend_exp_3; 
            set_dividend_exp_2;
            set_dividend_exp_1; 
            set_dividend_exp_0;
        }
        const entries = {
            (0..0,1..1):            set_dividend_exp_0();
            (0..0,2..3):            set_dividend_exp_1();
            (0..0,4..7):            set_dividend_exp_2();
            (0..0,8..15):           set_dividend_exp_3();
            (0..0,16..31):          set_dividend_exp_4();
            (0..0,32..63):          set_dividend_exp_5();
            (0..0,64..127):         set_dividend_exp_6();
            (0..0,128..255):        set_dividend_exp_7();
            (0..0,256..511):        set_dividend_exp_8();
            (0..0,512..1023):       set_dividend_exp_9();
            (0..0,1024..2047):      set_dividend_exp_10();
            (0..0,2048..4095):      set_dividend_exp_11();
            (0..0,4096..8191):      set_dividend_exp_12();
            (0..0,8192..16383):     set_dividend_exp_13();
            (0..0,16384..32767):    set_dividend_exp_14();
            (0..0,32768..65535):    set_dividend_exp_15();
            (1..1,_):               set_dividend_exp_16();
            (2..3,_):               set_dividend_exp_17();
            (4..7,_):               set_dividend_exp_18();
            (8..15,_):              set_dividend_exp_19();
            (16..31,_):             set_dividend_exp_20();
            (32..63,_):             set_dividend_exp_21();
            (64..127,_):            set_dividend_exp_22();
            (128..255,_):           set_dividend_exp_23();
            (256..511,_):           set_dividend_exp_24();
            (512..1023,_):          set_dividend_exp_25();
            (1024..2047,_):         set_dividend_exp_26();
            (2048..4095,_):         set_dividend_exp_27();
            (4096..8191,_):         set_dividend_exp_28();
            (8192..16383,_):        set_dividend_exp_29();
            (16384..32767,_):       set_dividend_exp_30();
            (32768..65535,_):       set_dividend_exp_31();
        }
    }

    action get_delta_exp() {
        meta.delta_exp = meta.exp_dividend - meta.exp_divisor;
        meta.delta_exp_sat = meta.exp_dividend |-| meta.exp_divisor;
    }

    @stage(2)
    table get_delta_exp_t {
        actions = { get_delta_exp;}
        default_action = get_delta_exp();
        size = 1;
    }

    Register<bit<8>,bit<1>>(1) delta_exp_checker;
    RegisterAction<bit<8>,bit<1>,bit<1>>(delta_exp_checker) _judge_delta_exp = {
        void apply(inout bit<8> reg_data, out bit<1> result) {
            reg_data = 0;
            if(meta.delta_exp_sat > 0){
                result = 0;
            } else if(meta.delta_exp == 0) {
                result = 0;
            } else {
                result = 1;
            }
        }
    };

    action judge_delta_exp() {
        meta.res1 = _judge_delta_exp.execute(0);
    }

    @stage(3)
    table judge_delta_exp_t {
        actions = { judge_delta_exp;}
        default_action = judge_delta_exp();
        size = 1;
    }

    action shift_0() {
        meta.shifted_divisor = hdr.div.divisor;
        hdr.div.quotient = hdr.div.quotient + 1;
    }

    action shift_1() {
        meta.shifted_divisor = hdr.div.divisor << 1;
        hdr.div.quotient = hdr.div.quotient + 2;
    }

    action shift_2() {
        meta.shifted_divisor = hdr.div.divisor << 2;
        hdr.div.quotient = hdr.div.quotient + 4;
    }

    action shift_3() {
        meta.shifted_divisor = hdr.div.divisor << 3;
        hdr.div.quotient = hdr.div.quotient + 8;
    }

    action shift_4() {
        meta.shifted_divisor = hdr.div.divisor << 4;
        hdr.div.quotient = hdr.div.quotient + 16;
    }

    action shift_5() {
        meta.shifted_divisor = hdr.div.divisor << 5;
        hdr.div.quotient = hdr.div.quotient + 32;
    }

    action shift_6() {
        meta.shifted_divisor = hdr.div.divisor << 6;
        hdr.div.quotient = hdr.div.quotient + 64;
    }

    action shift_7() {
        meta.shifted_divisor = hdr.div.divisor << 7;
        hdr.div.quotient = hdr.div.quotient + 128;
    }

    action shift_8() {
        meta.shifted_divisor = hdr.div.divisor << 8;
        hdr.div.quotient = hdr.div.quotient + 256;
    }

    action shift_9() {
        meta.shifted_divisor = hdr.div.divisor << 9;
        hdr.div.quotient = hdr.div.quotient + 512;
    }

    action shift_10() {
        meta.shifted_divisor = hdr.div.divisor << 10;
        hdr.div.quotient = hdr.div.quotient + 1024;
    }

    action shift_11() {
        meta.shifted_divisor = hdr.div.divisor << 11;
        hdr.div.quotient = hdr.div.quotient + 2048;
    }

    action shift_12() {
        meta.shifted_divisor = hdr.div.divisor << 12;
        hdr.div.quotient = hdr.div.quotient + 4096;
    }

    action shift_13() {
        meta.shifted_divisor = hdr.div.divisor << 13;
        hdr.div.quotient = hdr.div.quotient + 8192;
    }

    action shift_14() {
        meta.shifted_divisor = hdr.div.divisor << 14;
        hdr.div.quotient = hdr.div.quotient + 16384;
    }

    action shift_15() {
        meta.shifted_divisor = hdr.div.divisor << 15;
        hdr.div.quotient = hdr.div.quotient + 32768;
    }

    action shift_16() {
        meta.shifted_divisor = hdr.div.divisor << 16;
        hdr.div.quotient = hdr.div.quotient + 65536;
    }

    action shift_17() {
        meta.shifted_divisor = hdr.div.divisor << 17;
        hdr.div.quotient = hdr.div.quotient + 131072;
    }

    action shift_18() {
        meta.shifted_divisor = hdr.div.divisor << 18;
        hdr.div.quotient = hdr.div.quotient + 262144;
    }

    action shift_19() {
        meta.shifted_divisor = hdr.div.divisor << 19;
        hdr.div.quotient = hdr.div.quotient + 524288;
    }

    action shift_20() {
        meta.shifted_divisor = hdr.div.divisor << 20;
        hdr.div.quotient = hdr.div.quotient + 1048576;
    }

    action shift_21() {
        meta.shifted_divisor = hdr.div.divisor << 21;
        hdr.div.quotient = hdr.div.quotient + 2097152;
    }

    action shift_22() {
        meta.shifted_divisor = hdr.div.divisor << 22;
        hdr.div.quotient = hdr.div.quotient + 4194304;
    }

    action shift_23() {
        meta.shifted_divisor = hdr.div.divisor << 23;
        hdr.div.quotient = hdr.div.quotient + 8388608;
    }

    action shift_24() {
        meta.shifted_divisor = hdr.div.divisor << 24;
        hdr.div.quotient = hdr.div.quotient + 16777216;
    }

    action shift_25() {
        meta.shifted_divisor = hdr.div.divisor << 25;
        hdr.div.quotient = hdr.div.quotient + 33554432;
    }

    action shift_26() {
        meta.shifted_divisor = hdr.div.divisor << 26;
        hdr.div.quotient = hdr.div.quotient + 67108864;
    }

    action shift_27() {
        meta.shifted_divisor = hdr.div.divisor << 27;
        hdr.div.quotient = hdr.div.quotient + 134217728;
    }

    action shift_28() {
        meta.shifted_divisor = hdr.div.divisor << 28;
        hdr.div.quotient = hdr.div.quotient + 268435456;
    }

    action shift_29() {
        meta.shifted_divisor = hdr.div.divisor << 29;
        hdr.div.quotient = hdr.div.quotient + 536870912;
    }

    @stage(4)
    table shift_t {
        key = {
            meta.delta_exp: exact;
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
            shift_20;
            shift_21; 
            shift_22; 
            shift_23;
            shift_24; 
            shift_25; 
            shift_26;
            shift_27; 
            shift_28; 
            shift_29;
            NoAction;
        }
        default_action = NoAction();
        size = 32;
        const entries = {
            0:  shift_0(); 
            1:  shift_1(); 
            2:  shift_2();
            3:  shift_3(); 
            4:  shift_4(); 
            5:  shift_5();
            6:  shift_6(); 
            7:  shift_7(); 
            8:  shift_8();
            9:  shift_9(); 
            10: shift_10(); 
            11: shift_11();
            12: shift_12(); 
            13: shift_13(); 
            14: shift_14();
            15: shift_15(); 
            16: shift_16(); 
            17: shift_17();
            18: shift_18(); 
            19: shift_19(); 
            20: shift_20();
            21: shift_21(); 
            22: shift_22(); 
            23: shift_23();
            24: shift_24(); 
            25: shift_25(); 
            26: shift_26();
            27: shift_27(); 
            28: shift_28(); 
            29: shift_29();
        }
    }

    action minus_dividend() {
        meta.dividend_hi = (hdr.div.dividend - meta.shifted_divisor)[31:16];
        meta.dividend_lo = (hdr.div.dividend - meta.shifted_divisor)[15:0];
        hdr.div.dividend = hdr.div.dividend - meta.shifted_divisor;    
    }

    @stage(5)
    table minus_dividend_t {
        actions = { minus_dividend;}
        default_action = minus_dividend();
        size = 1;
    }

    action get_delta_val() {
        meta.delta_val = hdr.div.dividend - hdr.div.divisor;
        meta.delta_val_sat = hdr.div.dividend |-| hdr.div.divisor;
    }

    @stage(4)
    table get_delta_val_t {
        actions = { get_delta_val;}
        default_action = get_delta_val();
        size = 1;
    }

    Register<bit<32>,bit<1>>(1) delta_val_checker1;
    RegisterAction<bit<32>,bit<1>,bit<1>>(delta_val_checker1) _judge_delta_val1 = {
        void apply(inout bit<32> reg_data, out bit<1> result) {
            reg_data = 0;
            if(meta.delta_val == 0) {
                result = 1; // 6 / 6
            // } else if(meta.delta_val_sat == 0) {
            //     result = 2; // 6 / 7
            } else {
                result = 0; // 7 / 6
            }
        }
    };

    action judge_delta_val1() {
        meta.res2 = _judge_delta_val1.execute(0);
    }

    @stage(5)
    table judge_delta_val1_t {
        actions = { judge_delta_val1;}
        default_action = judge_delta_val1();
        size = 1;
    }

    Register<bit<32>,bit<1>>(1) delta_val_checker2;
    RegisterAction<bit<32>,bit<1>,bit<1>>(delta_val_checker2) _judge_delta_val2 = {
        void apply(inout bit<32> reg_data, out bit<1> result) {
            reg_data = 0;
            if(meta.delta_val_sat == 0) {
                result = 1;
            } else {
                result = 0;
            }
        }
    };

    action judge_delta_val2() {
        meta.res3 = _judge_delta_val2.execute(0);
    }

    @stage(5)
    table judge_delta_val2_t {
        actions = { judge_delta_val2;}
        default_action = judge_delta_val2();
        size = 1;
    }

    action dividend_eq_divisor() {
        hdr.div.quotient = hdr.div.quotient + 1;
        hdr.div.remainder = 0;
        hdr.div.isDone = 1;
    }

    action dividend_lt_divisor() {
        hdr.div.remainder = hdr.div.dividend;
        hdr.div.isDone = 1;
    }

    action dividend_gt_divisor() {
        hdr.div.quotient = hdr.div.quotient + 1;
        hdr.div.remainder = hdr.div.dividend - hdr.div.divisor;
        hdr.div.isDone = 1;
    }

    @stage(8)
    table set_done_t {
        key = {
            meta.res2:  exact;
            meta.res3:  exact;
        }
        actions = {
            dividend_eq_divisor;
            dividend_gt_divisor;
            dividend_lt_divisor;
            NoAction;
        }
        default_action = NoAction();
        const entries = {
            (1,0):  dividend_eq_divisor();// impossible situation but for robustness
            (1,1):  dividend_eq_divisor(); 
            (0,1):  dividend_lt_divisor();
            (0,0):  dividend_gt_divisor();
        }
    }

#if ENABLE_AGAIN

    @stage(6)
    table set_dividend_again_t {
        key = {
            meta.dividend_hi:   range;
            meta.dividend_lo:   range;
        }
        actions = {
            set_dividend_exp_31; 
            set_dividend_exp_30;
            set_dividend_exp_29; 
            set_dividend_exp_28;
            set_dividend_exp_27; 
            set_dividend_exp_26;
            set_dividend_exp_25; 
            set_dividend_exp_24;
            set_dividend_exp_23; 
            set_dividend_exp_22;
            set_dividend_exp_21; 
            set_dividend_exp_20;
            set_dividend_exp_19; 
            set_dividend_exp_18;
            set_dividend_exp_17; 
            set_dividend_exp_16;
            set_dividend_exp_15; 
            set_dividend_exp_14;
            set_dividend_exp_13; 
            set_dividend_exp_12;
            set_dividend_exp_11; 
            set_dividend_exp_10;
            set_dividend_exp_9; 
            set_dividend_exp_8;
            set_dividend_exp_7; 
            set_dividend_exp_6;
            set_dividend_exp_5; 
            set_dividend_exp_4;
            set_dividend_exp_3; 
            set_dividend_exp_2;
            set_dividend_exp_1; 
            set_dividend_exp_0;
        }
        const entries = {
            (0..0,1..1):            set_dividend_exp_0();
            (0..0,2..3):            set_dividend_exp_1();
            (0..0,4..7):            set_dividend_exp_2();
            (0..0,8..15):           set_dividend_exp_3();
            (0..0,16..31):          set_dividend_exp_4();
            (0..0,32..63):          set_dividend_exp_5();
            (0..0,64..127):         set_dividend_exp_6();
            (0..0,128..255):        set_dividend_exp_7();
            (0..0,256..511):        set_dividend_exp_8();
            (0..0,512..1023):       set_dividend_exp_9();
            (0..0,1024..2047):      set_dividend_exp_10();
            (0..0,2048..4095):      set_dividend_exp_11();
            (0..0,4096..8191):      set_dividend_exp_12();
            (0..0,8192..16383):     set_dividend_exp_13();
            (0..0,16384..32767):    set_dividend_exp_14();
            (0..0,32768..65535):    set_dividend_exp_15();
            (1..1,_):               set_dividend_exp_16();
            (2..3,_):               set_dividend_exp_17();
            (4..7,_):               set_dividend_exp_18();
            (8..15,_):              set_dividend_exp_19();
            (16..31,_):             set_dividend_exp_20();
            (32..63,_):             set_dividend_exp_21();
            (64..127,_):            set_dividend_exp_22();
            (128..255,_):           set_dividend_exp_23();
            (256..511,_):           set_dividend_exp_24();
            (512..1023,_):          set_dividend_exp_25();
            (1024..2047,_):         set_dividend_exp_26();
            (2048..4095,_):         set_dividend_exp_27();
            (4096..8191,_):         set_dividend_exp_28();
            (8192..16383,_):        set_dividend_exp_29();
            (16384..32767,_):       set_dividend_exp_30();
            (32768..65535,_):       set_dividend_exp_31();
        }
    }

    @stage(7)
    table get_delta_exp_again_t {
        actions = { get_delta_exp;}
        default_action = get_delta_exp();
        size = 1;
    }

    Register<bit<8>,bit<1>>(1) delta_exp_checker_again;
    RegisterAction<bit<8>,bit<1>,bit<1>>(delta_exp_checker_again) _judge_delta_exp_again = {
        void apply(inout bit<8> reg_data, out bit<1> result) {
            reg_data = 0;
            if(meta.delta_exp_sat > 0){
                result = 0;
            } else if(meta.delta_exp == 0) {
                result = 0;
            } else {
                result = 1;
            }
        }
    };

    action judge_delta_exp_again() {
        meta.res4 = _judge_delta_exp_again.execute(0);
    }

    @stage(8)
    table judge_delta_exp_again_t {
        actions = { judge_delta_exp_again;}
        default_action = judge_delta_exp_again();
        size = 1;
    }

    @stage(9)
    table shift_again_t {
        key = {
            meta.delta_exp: exact;
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
            shift_20;
            shift_21; 
            shift_22; 
            shift_23;
            shift_24; 
            shift_25; 
            shift_26;
            shift_27; 
            shift_28; 
            shift_29;
            NoAction;
        }
        default_action = NoAction();
        size = 32;
        const entries = {
            0:  shift_0(); 
            1:  shift_1(); 
            2:  shift_2();
            3:  shift_3(); 
            4:  shift_4(); 
            5:  shift_5();
            6:  shift_6(); 
            7:  shift_7(); 
            8:  shift_8();
            9:  shift_9(); 
            10: shift_10(); 
            11: shift_11();
            12: shift_12(); 
            13: shift_13(); 
            14: shift_14();
            15: shift_15(); 
            16: shift_16(); 
            17: shift_17();
            18: shift_18(); 
            19: shift_19(); 
            20: shift_20();
            21: shift_21(); 
            22: shift_22(); 
            23: shift_23();
            24: shift_24(); 
            25: shift_25(); 
            26: shift_26();
            27: shift_27(); 
            28: shift_28(); 
            29: shift_29();
        }
    }

    @stage(10)
    table minus_dividend_again_t {
        actions = { minus_dividend;}
        default_action = minus_dividend();
        size = 1;
    }

    @stage(9)
    table get_delta_val_again_t {
        actions = { get_delta_val;}
        default_action = get_delta_val();
        size = 1;
    }

    Register<bit<32>,bit<1>>(1) delta_val_checker1_again;
    RegisterAction<bit<32>,bit<1>,bit<1>>(delta_val_checker1_again) _judge_delta_val1_again = {
        void apply(inout bit<32> reg_data, out bit<1> result) {
            reg_data = 0;
            if(meta.delta_val == 0) {
                result = 1; // 6 / 6
            // } else if(meta.delta_val_sat == 0) {
            //     result = 2; // 6 / 7
            } else {
                result = 0; // 7 / 6
            }
        }
    };

    action judge_delta_val1_again() {
        meta.res5 = _judge_delta_val1_again.execute(0);
    }

    @stage(10)
    table judge_delta_val1_again_t {
        actions = { judge_delta_val1_again;}
        default_action = judge_delta_val1_again();
        size = 1;
    }

    Register<bit<32>,bit<1>>(1) delta_val_checker2_again;
    RegisterAction<bit<32>,bit<1>,bit<1>>(delta_val_checker2_again) _judge_delta_val2_again = {
        void apply(inout bit<32> reg_data, out bit<1> result) {
            reg_data = 0;
            if(meta.delta_val_sat == 0) {
                result = 1;
            } else {
                result = 0;
            }
        }
    };

    action judge_delta_val2_again() {
        meta.res6 = _judge_delta_val2_again.execute(0);
    }

    @stage(10)
    table judge_delta_val2_again_t {
        actions = { judge_delta_val2_again;}
        default_action = judge_delta_val2_again();
        size = 1;
    }

    @stage(11)
    table set_done_again_t {
        key = {
            meta.res5:  exact;
            meta.res6:  exact;
        }
        actions = {
            dividend_eq_divisor;
            dividend_gt_divisor;
            dividend_lt_divisor;
            NoAction;
        }
        default_action = NoAction();
        const entries = {
            (1,0):  dividend_eq_divisor();// impossible situation but for robustness
            (1,1):  dividend_eq_divisor(); 
            (0,1):  dividend_lt_divisor();
            (0,0):  dividend_gt_divisor();
        }
    }

#endif

    apply {
        if(eg_intr_md.egress_port == RECIRC_PORT) {
            set_divisor_t.apply();  // stage 0
            
            set_dividend_t.apply(); // stage 1
            // lookup
            get_delta_exp_t.apply(); // stage 2
            judge_delta_exp_t.apply(); // stage 3
            if(meta.res1 == 0) {
                shift_t.apply(); // stage 4
                minus_dividend_t.apply(); // stage 5

#if  ENABLE_AGAIN

                set_dividend_again_t.apply(); // stage 6
                // lookup
                get_delta_exp_again_t.apply(); // stage 7
                judge_delta_exp_again_t.apply(); // stage 8
                if(meta.res4 == 0) {
                    shift_again_t.apply(); // stage 9
                    minus_dividend_again_t.apply(); // stage 10
                } else {
                    get_delta_val_again_t.apply(); // stage 9
                    judge_delta_val1_again_t.apply(); // stage 10
                    judge_delta_val2_again_t.apply(); // stage 10
                    set_done_again_t.apply(); // stage 11
                }   

#endif

            } else {
                get_delta_val_t.apply(); // stage 4
                judge_delta_val1_t.apply(); // stage 5
                judge_delta_val2_t.apply(); // stage 5
                set_done_t.apply(); // stage 8
            }
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
