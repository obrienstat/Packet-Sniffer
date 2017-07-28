import sys
import socket
import struct
import textwrap
import binascii
import pcapy
# from pcapy import pcapy


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
        print('Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # for all IPv4 traffic
        if eth_proto == 8:
            print('\n\tIPv4')
            ipv4_proto, ipv4_data = ipv4_packet(eth_data)

            # TCP
            if ipv4_proto == 6:
                print('\n\t\tTCP Segment:')
                tcp_segment(ipv4_data)

            # ICMP
            elif ipv4_proto == 1:
                print('\n\t\tICMP Packet:')
                icmp_packet(ipv4_data)

            # UDP
            elif ipv4_proto == 17:
                print('\n\t\tUDP Segment:')

        # must be IPv6 traffic
        else:
            ipv6_packet(eth_data)

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
    print('\tProtocol: {}'.format(proto))
    print('\tFrom: {}'.format(get_ipv4_addr(src)))
    print('\tTo: {}'.format(get_ipv4_addr(target)))

    # return protocol and the actual data
    return proto, data[header_length:]


# returns formated ipv4 address
def get_ipv4_addr(unformatted_addr):
    return '.'.join(map(str, unformatted_addr))


def ipv6_packet(data):
    """
        Breaks open the ipv6 header and returns the payload while
        printing all the relevant information inside the header
        
    :param data: the ipv6 data
    :return: the payload
    """
    print('unpack the ipv6 header to retrieve the payload')


# Unpack the ICMP packet
def icmp_packet(data):
    _type, code, check_sum = struct.unpack('! B B H', data[:4])
    print('\t\tType: {}, Code: {}, CheckSum: {}'.format(_type, code, check_sum))


# Unpack the TCP packet/segment
def tcp_segment(data):

    # need the src port and stuff
    (src_port, dest_port, sequence, ack, offset_r_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_r_flags >> 12) * 4
    flag_urg = (offset_r_flags & 32) >> 5
    flag_ack = (offset_r_flags & 16) >> 4
    flag_psh = (offset_r_flags & 8) >> 3
    flag_rst = (offset_r_flags & 4) >> 2
    flag_syn = (offset_r_flags & 2) >> 1
    flag_fin = offset_r_flags & 1
    data = data[offset:]

    print('\t\tSource Port: {}'.format(src_port))
    print('\t\tDestination Port: {}'.format(dest_port))
    print('\t\tSequence: {}'.format(sequence))
    print('\t\tAcknowledgement: {}'.format(ack))
    print(format_multi_line('\t\t\t', data))


# Unpack UDP Segment
def udp_segment(data):
    src_port, dst_port, size = struct.unpack('! H H 2x H', data[:8])
    print('\t\tSource Port: {}'.format(src_port))
    print('\t\tDestination Port: {}'.format(dst_port))
    print('\t\tSize: {}'.format(size))

    return data[8:]


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


if __name__ == '__main__':

    if len(sys.argv) < 2:
        # error no file
        print('Error: No file name detected')
        sys.exit(1)

    # Read the file from the cmd line, throw error if no file
    main(sys.argv[1])
