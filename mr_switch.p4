#include <core.p4>
#include <v1model.p4>

typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;

header Ethernet_h {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> ethernetType;
}


header IPv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    IPv4Address srcAddr;
    IPv4Address dstAddr;
    //varbit<320>  options;
}

header UDP_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplength;
    bit<16> checksum;
}

header TCP_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqnumber;
    bit<32> acknumber;
    bit<32> command;
    bit<16> windowsize;
    bit<16> checksum;
}

struct headers {
    Ethernet_h ethernet;
    IPv4_h ipv4;
    UDP_h udp;
    TCP_h tcp;
}


struct mystruct_t {
    bit<32> a;
}


struct metadata {
    mystruct_t mystruct1;
}

typedef tuple<bit<4>, bit<4>, bit<8>, varbit<56>> myTuple1;

error {
    Ipv4ChecksumError
}


parser mr_Parser(packet_in pkt, out headers hdr, 
                    inout metadata meta, inout standard_metadata_t stdmeta)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethernetType) {
            0x0800 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x11 : parse_udp;
            0x06 : parse_tcp;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

}


control mr_Ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t stdmeta)
{
    //route number
    register<bit<32>>(1) rgt;

    bit<32> route_position = 0;

    bit<32> route_number = 1;

    action forward(bit<9> port) {
        stdmeta.egress_spec = port;
    }

    action read_route() {
        rgt.read(route_number, route_position);
    }

    action write_route() {
        rgt.write(route_position, route_number + 1 > 3 ? 1 : route_number + 1);
    }

    table match_inport {
        key = {
            stdmeta.ingress_port:exact;
        }
        actions = {forward;}
    }

    table match_ip_udp {
        key = {
            hdr.ipv4.dstAddr:exact;
            hdr.udp.dstPort:exact;
        }
        actions = {forward;}
    }

    table match_route_1 {
        key = {
            hdr.ipv4.dstAddr:exact;
            hdr.tcp.dstPort:exact;
        }
        actions = {forward;}
    }

    table match_route_2 {
        key = {
            hdr.ipv4.dstAddr:exact;
            hdr.tcp.dstPort:exact;
        }
        actions = {forward;}
    }

    table match_route_3 {
        key = {
            hdr.ipv4.dstAddr:exact;
            hdr.tcp.dstPort:exact;
        }
        actions = {forward;}
    }

    table acquire_route {
        actions = {read_route;}
    }

    table update_route {
        key = {
            hdr.ipv4.dstAddr:exact;
            hdr.tcp.dstPort:exact;
        }
        actions = {write_route;}
    }

    apply {

        match_inport.apply();

        acquire_route.apply();
        if (hdr.ethernet.ethernetType == 0x0800) {
            match_ip_udp.apply();
            if (route_number == 1) {
                match_route_1.apply();
            }
            else if (route_number == 2) {
                match_route_2.apply();
            }
            else if (route_number == 3) {
                match_route_3.apply();
            }
            update_route.apply();
        }
    }

}



control mr_Egress(inout headers hdr, inout metadata meta, inout standard_metadata_t stdmeta)
{   

    apply {

    }
}

control mr_VerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true,
        {   hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr//,hdr.ipv4.options
        },hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control mr_UpdateChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true,
        {   hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr//,hdr.ipv4.options
        },hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }    
}

control mr_Deparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }

}

V1Switch<headers, metadata>(mr_Parser(), mr_VerifyChecksum(), mr_Ingress(), mr_Egress(), mr_UpdateChecksum(),mr_Deparser()) main;