"""
    Created by Status O'Brien on 29/07/17,
    Some source code and modifications have been taken from BuckyRobers (The New Boston)
    on github: https://github.com/buckyroberts/Python-Packet-Sniffer

    This is my version of a packet sniffer
"""

import sys
import socket
import struct
import binascii
# import pcapy
from pcapy import pcapy  # for when running on linux distro


def main(pcap_filename):
    """
        Here we read our pcap file. We then start by unpacking the ethernet frame,
        from there we can determine the protocol/or the type of packet we are dealing with,
        we then further process that packet until it is fully opened.
    """

    print('Opening the file: {}'.format(pcap_filename))
    pcap_reader = pcapy.open_offline(pcap_filename)

    i = 0
    while True:
        i = i + 1   # our counter for each packet

        meta, raw_data = pcap_reader.next()

        # check if anymore packets to process
        if len(raw_data) < 1:
            break

        dest_mac, src_mac, eth_proto, eth_data = ethernet_frame(raw_data)
        print('\nEthernet Frame: #{}'.format(i))
        print('Destination MAC: {}, Source MAC: {}'.format(dest_mac, src_mac))

        # for all IPv4 traffic
        if eth_proto == 8:
            print('\nEthernet Protocol: IPv4')
            ipv4_proto, ipv4_data = ipv4_packet(eth_data)

            # TCP
            if ipv4_proto == 6:
                print('\tProtocol: TCP')
                tcp_segment(ipv4_data)

            # ICMP
            elif ipv4_proto == 1:
                print('\tProtocol: ICMP')
                icmp_packet(ipv4_data)

            # UDP
            elif ipv4_proto == 17:
                print('\tProtocol: UDP')
                udp_segment(ipv4_data)

        # must be IPv6 traffic
        elif eth_proto == 56710:
            print('\nEthernet Protocol: IPv6')
            next_header, data = ipv6_packet(eth_data)

            # TCP
            if next_header == 6:
                print('\tProtocol: TCP')
                tcp_segment(data)

            # UDP
            elif next_header == 17:
                print('\tProtocol: UDP')
                udp_segment(data)

        else:
            print('\n\tUnknown Protocol: {}'.format(eth_proto))

    # end of file
    print('\nFile reading end')
    sys.exit(0)  # exit gracefully


def ethernet_frame(data):
    """
        Unpacks our ethernet frame. 
    """
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(mac_bytes):
    """
        Converts the mac address into readable ascii format.
        Corresponding to xx:xx:xx:xx:xx:xx
    """
    mac_string = binascii.hexlify(mac_bytes).decode('ascii')
    mac_pairs = [i + j for i, j in zip(mac_string[0::2], mac_string[1::2])]
    return ':'.join(mac_pairs).upper()


# returns formated ipv4 address xxx.xxx.x.x
def get_ipv4_addr(unformatted_addr):
    return '.'.join(map(str, unformatted_addr))


# returns formatted ipv6 address xxxx::xxxx
def get_ipv6_addr(mac_bytes):
    return socket.inet_ntop(socket.AF_INET6, mac_bytes).upper()


def ipv4_packet(data):
    """
        The function strips the IPv4 Header so we can determine the ip addresses,
        and retrieve the protocol to determine what to do next
    """

    # we must break open the ipv4 header before we get to the payload
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    # we need the length of the header because it is used to determine
    # where the actual data starts.

    # start unpacking everything
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    print('\tVersion: {}'.format(version))
    print('\tHeader Length: {}'.format(header_length))
    print('\tTTL: {}'.format(ttl))
    print('\tFrom: {}'.format(get_ipv4_addr(src)))
    print('\tTo: {}'.format(get_ipv4_addr(target)))

    # return protocol and the actual data
    return proto, data[header_length:]


def ipv6_packet(data):
    """
        Breaks open the ipv6 header and returns the payload while
        printing all the relevant information inside the header
    """
    version = data[0] >> 4
    traffic_class = (data[0] & 0xF) * 16 + (data[1] >> 4)
    payload_length = int(binascii.hexlify(data[4:6]).decode('ascii'), 16)  # this sucked! must be a better way
    next_header = data[6]
    hop_limit = data[7]
    src_address = get_ipv6_addr(data[8:24])
    target_address = get_ipv6_addr(data[24:40])

    print('\tVersion: {}'.format(version))
    print('\tTraffic Class: {}'.format(traffic_class))
    print('\tHop Limit: {}'.format(hop_limit))
    print('\tFrom: {}'.format(src_address))
    print('\tTo: {}'.format(target_address))
    print('\tPayload: {} bytes'.format(payload_length))

    return next_header, data[40:]  # return our payload length


# Unpack the ICMP packet
def icmp_packet(data):
    _type, code, check_sum = struct.unpack('! B B H', data[:4])
    print('\t\tType: {}, Code: {}, CheckSum: {}'.format(_type, code, check_sum))


def icmp_v6_packet(data):
    print('ipv6icmp')


# Unpack the TCP packet/segment
def tcp_segment(data):
    (src_port, dest_port, sequence, ack, offset_r_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_r_flags >> 12) * 4
    flag_urg = (offset_r_flags & 32) >> 5
    flag_ack = (offset_r_flags & 16) >> 4
    flag_psh = (offset_r_flags & 8) >> 3
    flag_rst = (offset_r_flags & 4) >> 2
    flag_syn = (offset_r_flags & 2) >> 1
    flag_fin = offset_r_flags & 1

    print('\t\tSource Port: {}'.format(src_port))
    print('\t\tDestination Port: {}'.format(dest_port))
    print('\t\tSequence: {}'.format(sequence))
    print('\t\tAcknowledgement: {}'.format(ack))
    print('\t\tPayload: {} bytes\n'.format(sys.getsizeof(data) - 33))

    print(data[offset:])


# Unpack UDP Segment
def udp_segment(data):
    src_port, dst_port, size = struct.unpack('! H H 2x H', data[:8])
    print('\t\tSource Port: {}'.format(src_port))
    print('\t\tDestination Port: {}'.format(dst_port))
    print('\t\tSize: {}'.format(size))

    print(data[8:])


if __name__ == '__main__':

    if len(sys.argv) < 2:
        # error no file
        print('Error: No file name detected')
        sys.exit(1)

    # Read the file from the cmd line, throw error if no file
    main(sys.argv[1])
