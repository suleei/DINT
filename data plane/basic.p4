/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define DDPV_DATA_LEN 12
#define DDPV_REPORT_LEN 10
#define DDPV_DATA_LEN_4B 3
#define BLOOM_LEN 96

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 0x6;
const bit<8> TYPE_UDP = 0x11;
const bit<32> SKETCH_LEN = 100000;
const bit<7> BLOOM_INDEX_LEN = BLOOM_LEN;
const bit<9> DROP_PORT = 511;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9> port_t;
typedef bit<6> suffix_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}


header ddpv_data_t {
    bit<BLOOM_LEN>  bloom_filter;
}

header ddpv_report_t {
    macAddr_t device_id;
    ip4Addr_t ip_dst;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}



struct metadata {
    bit<32>      mec_index1;
    bit<32>      mec_index2;
    bit<32>      mec_index3;
    bit<32>      sp_index1;
    bit<32>      sp_index2;
    bit<32>      sp_index3;

    bit<7>       bloom_index1;
    bit<7>       bloom_index2;
    bit<7>       bloom_index3;
    bit<7>       bloom_index4;

    bit<BLOOM_LEN>       bloom_value1;
    bit<BLOOM_LEN>       bloom_value2;
    bit<BLOOM_LEN>       bloom_value3;
    bit<BLOOM_LEN>       bloom_value4;

    suffix_t       suffix;

}

struct headers {
    ethernet_t    ethernet;
    ipv4_t        ipv4;  
    ddpv_data_t   ddpv_data;
    ddpv_report_t ddpv_report;
    tcp_t         tcp;
    udp_t         udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl){
            5: parse_l4_proto;
            8: parse_ddpv_data;
        }
    }

    state parse_l4_proto{
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default:  accept;
        }
    }

    state parse_ddpv_data {
        packet.extract(hdr.ddpv_data);
        transition parse_l4_proto;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    register<port_t>(SKETCH_LEN) mec_port_reg1;
    register<port_t>(SKETCH_LEN) mec_port_reg2;
    register<port_t>(SKETCH_LEN) mec_port_reg3;

    register<port_t>(SKETCH_LEN) sp_port_reg1;
    register<port_t>(SKETCH_LEN) sp_port_reg2;
    register<port_t>(SKETCH_LEN) sp_port_reg3;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, suffix_t suffix) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        meta.suffix = suffix;
    }

    action calculate_sketch_index() {
        hash(meta.sp_index1,HashAlgorithm.crc32_custom,32w0,{hdr.ipv4.dstAddr},SKETCH_LEN);
        hash(meta.sp_index2,HashAlgorithm.crc32_custom,32w0,{hdr.ipv4.dstAddr},SKETCH_LEN);
        hash(meta.sp_index3,HashAlgorithm.crc32_custom,32w0,{hdr.ipv4.dstAddr},SKETCH_LEN);
        bit<32> mec_id = hdr.ipv4.dstAddr & 0xffffff00;
        hash(meta.mec_index1,HashAlgorithm.crc32_custom,32w0,{mec_id},SKETCH_LEN);
        hash(meta.mec_index2,HashAlgorithm.crc32_custom,32w0,{mec_id},SKETCH_LEN);
        hash(meta.mec_index3,HashAlgorithm.crc32_custom,32w0,{mec_id},SKETCH_LEN);
    }

    action calculate_bloom_filter_index() {
        hash(meta.bloom_index1,HashAlgorithm.crc32_custom,32w0,{hdr.ethernet.srcAddr},BLOOM_INDEX_LEN);
        hash(meta.bloom_index2,HashAlgorithm.crc32_custom,32w0,{hdr.ethernet.srcAddr},BLOOM_INDEX_LEN);
        hash(meta.bloom_index3,HashAlgorithm.crc32_custom,32w0,{hdr.ethernet.srcAddr},BLOOM_INDEX_LEN);
        hash(meta.bloom_index4,HashAlgorithm.crc32_custom,32w0,{hdr.ethernet.srcAddr},BLOOM_INDEX_LEN);
        meta.bloom_value1=(bit<BLOOM_LEN>)1<<meta.bloom_index1;
        meta.bloom_value2=(bit<BLOOM_LEN>)1<<meta.bloom_index2;
        meta.bloom_value3=(bit<BLOOM_LEN>)1<<meta.bloom_index3;
        meta.bloom_value4=(bit<BLOOM_LEN>)1<<meta.bloom_index4;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        default_action = drop();
    }

    apply {
        port_t sp_v1;
        port_t sp_v2;
        port_t sp_v3;
        port_t sp_v;

        port_t mec_v1;
        port_t mec_v2;
        port_t mec_v3;
        port_t mec_v;

        if(hdr.ipv4.isValid()){
            if(hdr.ipv4.ttl==0) mark_to_drop(standard_metadata);
            else{
                ipv4_lpm.apply();
            }
            if(standard_metadata.egress_spec!=DROP_PORT&&!hdr.ddpv_report.isValid()&&(hdr.ipv4.protocol==TYPE_TCP || hdr.ipv4.protocol==TYPE_UDP)){
                bit<1> modification_marker=0;
                calculate_bloom_filter_index();
                bit<3> count=0;
                if(hdr.ddpv_data.isValid()){
                    if(meta.bloom_value1&hdr.ddpv_data.bloom_filter==meta.bloom_value1) count=count+1;
                    if(meta.bloom_value2&hdr.ddpv_data.bloom_filter==meta.bloom_value2) count=count+1;
                    if(meta.bloom_value3&hdr.ddpv_data.bloom_filter==meta.bloom_value3) count=count+1;
                    if(meta.bloom_value4&hdr.ddpv_data.bloom_filter==meta.bloom_value4) count=count+1;
                }

                if(count==4){
                    hdr.ddpv_data.setInvalid();
                    hdr.ethernet.dstAddr = 0xffffffffff17;
                    hdr.ipv4.ihl=5;
                    hdr.ipv4.protocol = 147;
                    hdr.ipv4.totalLen=34 + DDPV_REPORT_LEN;
                    hdr.ddpv_report.setValid();
                    hdr.ddpv_report.device_id = hdr.ethernet.srcAddr;
                    hdr.ddpv_report.ip_dst = hdr.ipv4.dstAddr;
                    hdr.ipv4.dstAddr = 0xffffff11;
                    truncate(34 + DDPV_REPORT_LEN);
                    standard_metadata.egress_spec = (port_t)42;
                }else{
                    calculate_sketch_index();

                    mec_port_reg1.read(mec_v1,(bit<32>)meta.mec_index1);
                    mec_port_reg2.read(mec_v2,(bit<32>)meta.mec_index2);
                    mec_port_reg3.read(mec_v3,(bit<32>)meta.mec_index3);
                    sp_port_reg1.read(sp_v1,(bit<32>)meta.sp_index1);
                    sp_port_reg2.read(sp_v2,(bit<32>)meta.sp_index2);
                    sp_port_reg3.read(sp_v3,(bit<32>)meta.sp_index3);

                    if(mec_v1==mec_v2&&mec_v2==mec_v3||mec_v1==mec_v2){
                        mec_v=mec_v1;
                    }else if(mec_v3==mec_v1||mec_v3==mec_v2){
                        mec_v=mec_v3;
                    }else {
                        mec_v=0;
                    }

                    if(sp_v1==sp_v2&&sp_v2==sp_v3||sp_v1==sp_v2){
                        sp_v=sp_v1;
                    }else if(sp_v3==sp_v1||sp_v3==sp_v2){
                        sp_v=sp_v3;
                    }else {
                        sp_v=0;
                    }

                    if(meta.suffix <=24){
                        mec_port_reg1.write((bit<32>)meta.mec_index1,standard_metadata.egress_spec);
                        mec_port_reg2.write((bit<32>)meta.mec_index2,standard_metadata.egress_spec);
                        mec_port_reg3.write((bit<32>)meta.mec_index3,standard_metadata.egress_spec);
                        if(sp_v!=0){
                            if(sp_v1==sp_v) sp_port_reg1.write((bit<32>)meta.sp_index1,standard_metadata.egress_spec);
                            if(sp_v2==sp_v) sp_port_reg2.write((bit<32>)meta.sp_index2,standard_metadata.egress_spec);
                            if(sp_v3==sp_v) sp_port_reg3.write((bit<32>)meta.sp_index3,standard_metadata.egress_spec);
                         if(sp_v!=standard_metadata.egress_spec) modification_marker=1;
                        }else{
                            if(mec_v!=standard_metadata.egress_spec) modification_marker=1;
                        }
                    }else{
                        sp_port_reg1.write((bit<32>)meta.sp_index1,standard_metadata.egress_spec);
                        sp_port_reg2.write((bit<32>)meta.sp_index2,standard_metadata.egress_spec);
                        sp_port_reg3.write((bit<32>)meta.sp_index3,standard_metadata.egress_spec);
                        if(sp_v!=standard_metadata.egress_spec)
                            modification_marker=1;
                        } 

                    if(modification_marker==1){
                       if(!hdr.ddpv_data.isValid()){
                            hdr.ddpv_data.setValid();
                            hdr.ddpv_data.bloom_filter=0;
                            hdr.ipv4.ihl=hdr.ipv4.ihl+DDPV_DATA_LEN_4B;
                            hdr.ipv4.totalLen=hdr.ipv4.totalLen+DDPV_DATA_LEN;
                        }
                        hdr.ddpv_data.bloom_filter = hdr.ddpv_data.bloom_filter | meta.bloom_value1;
                        hdr.ddpv_data.bloom_filter = hdr.ddpv_data.bloom_filter | meta.bloom_value2;
                        hdr.ddpv_data.bloom_filter = hdr.ddpv_data.bloom_filter | meta.bloom_value3;
                        hdr.ddpv_data.bloom_filter = hdr.ddpv_data.bloom_filter | meta.bloom_value4;
                    }
                }
            }     
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply { 
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: add deparser logic */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ddpv_data);
        packet.emit(hdr.ddpv_report);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
