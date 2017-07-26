import sys
import socket
import struct
import textwrap
import binascii

from pcapy import pcapy


def main(pcap_filename):

    print('Opening the file: {}'.format(pcap_filename))
    pcap_reader = pcapy.open_offline(pcap_filename)

    # meta, raw_data = pcap_reader.next()
    # print('meta: {}, data: {}'.format(meta, raw_data))
    # sys.exit(-1)

    while True:
        meta, raw_data = pcap_reader.next()

        if len(raw_data) < 1:
            break  # no more packets

        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame')
        print('\tDestination: {}, Source {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # for all IPv4 traffic
        if eth_proto == 8:
            ipv4_packet(data)
            # (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            # print('Version: {}, Header Length: {}, ttl: {}, protocol: {}'.format(version, header_length, ttl, proto))
            # print('Source: {}, Target: {}'.format(src, target))

        # must be IPv6 traffic
        else:
            print('IPv6 traffic')

    # end of file
    print('\nFile reading end')


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[:14]


def get_mac_addr(mac_bytes):
    mac_string = binascii.hexlify(mac_bytes).decode('ascii')
    mac_pairs = [i + j for i, j in zip(mac_string[0::2], mac_string[1::2])]
    return ':'.join(mac_pairs).upper()


def ipv4_packet(data):

    
    print('Data: {}'.format(data[0]))
    print('Data: {}'.format(data[1]))
    print('Data: {}'.format(data[2]))
    print('Data: {}'.format(data[3]))
    print('Data: {}'.format(data[4]))
    print('Data: {}'.format(data[5]))
    print('Data: {}'.format(data[6]))
    print('Data: {}'.format(data[7]))
    print('Data: {}'.format(data[8]))
    print('Data: {}'.format(data[9]))
    print('Data: {}'.format(data[10]))
        
    print('Raw_Data: {}'.format(data))

    # we must break open the ipv4 header before we get to the payload
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    print('Version Header Length: {}, Version: {}, Header Length: {}'.format(version_header_length, version,
                                                                             header_length))

    return

    # we need the length of the header because it is used to determine
    # where the actual data starts.

    # start unpacking everything
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    # print(''.format(struct.unpack('! 8x B B 2x 4s 4s', data[:20])))

    # return everything and the actual data
    return version, header_length, ttl, proto, get_ipv4_addr(src), get_ipv4_addr(target), data[header_length:]


# returns formated ipv4 address
def get_ipv4_addr(unformatted_addr):
    return '.'.join(map(str, unformatted_addr))




if __name__ == '__main__':

    if len(sys.argv) < 2:
        # error no file
        print('Error: No file name detected')
        sys.exit(1)

    # Read the file from the cmd line, throw error if no file
    main(sys.argv[1])
