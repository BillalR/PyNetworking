import sys
import socket
import struct
import textwrap

# main objective
def main():
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) # Isolate packets, raw sockets (All information), make sure works with all machines

	while True:
		raw_data, address = s.recvfrom(65536) #Receive the data and address destination or source
		dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data) #Take the data and pass it all to the function ethernet_frame
		print("\nEthernet Frame: ")
		print("\tDestination: {}, Source: {}, Protocol: {}".format(dest_mac,src_mac,eth_proto))

		#Make sure you are using Ethernet protocol 8
		if eth_proto == 8:
			(version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
			print('\t IPV4 PACKET: ')
			print('\t\t Version: {}, Header Length: {}, Time to Live: {}'.format(version, header_length, ttl))
			print('\t\t\t Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

		#Using ICMP Protocol: 1
		if proto == 1:
			(icmp_type, code, checksum, data) = icmp_packet(data)
			print('\t ICMP Packet: ')
			print('\t\t Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
			print('\t\t Data: ')
			print(format_multi_line('\t\t\t', data))

		#Using TCP Protocol: 6
		elif proto == 6:
			src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = tcp_segment(data)
			print('\t TCP Segment:')
			print('\t\t Source Port: {}, Desination Port: {}'.format(src_port, dest_port))
			print('\t\t Sequence: {}, Acknowledgement: {},'.format(sequence, acknowledgement))
			print('\t\t Flags: ')
			print('\t\t\t URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
			print('\t\t Data: ')
			print(format_multi_line('\t\t\t',data))

		#Using UDP Protocol: 17
		elif proto == 17:
			src_port, dest_port, length, data = udp_segment(data)
			print('\t UDP Segment: ')
			print('\t\t Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

		#Other
		else:
			print('\t Data:')
			print(format_multi_line('\t\t\t',data))

# Unpack ethernet fram
def ethernet_frame(data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14]) #6s means 6 charaters and H is a small unsigned int fotr the protocol
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC address
def get_mac_addr(bytes_addr): #(ie AA:BB:CC:DD:EE:FF)
	bytes_str = map('{:02x}'.format,bytes_addr) #Return mac address with 2 decimal places
	mac_addr = ':'.join(bytes_str).upper() #Join a colon for every section of 2 decimal place address
	return mac_addr


#Unpack IPV4 Packet
def ipv4_packet(data):
	version_header_length = data[0] #Version is the first byte of data
	version = version_header_length >> 4 #Push version header so you can get just the version (See IP Header Diagram)
	header_length = (version_header_length & 15)* 4 #Review this math
	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s',data[:20]) #All header information is 20 bytes long
	return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#Returns properly formatted IPv4 address
def ipv4(addr):
	return '.'.join(map(str,addr))

#Unpack ICMP Packet
def icmp_packet(data):
	icmp_type, code, checksum, data = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[4:]

#Unpack TCP Packet
def tcp_segment(data):
	(src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flags) >> 12 * 4
	flag_urg = (offset_reserved_flags & 32) >> 5
	flag_ack = (offset_reserved_flags & 16) >> 4
	flag_psh = (offset_reserved_flags & 8) >> 3
	flag_rst = (offset_reserved_flags & 4) >> 2
	flag_syn = (offset_reserved_flags & 2) >> 1
	flag_fin = (offset_reserved_flags & 1)
	return src_port, dest_port, sequence, acknowledgement,flack_urg, flack_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP Segment
def udp_segment(data):
	src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
	return src_port, dest_port, size, data[8:]

# Formats multi-line data
def format_multi_line(prefix, string, size=80):
	size -= len(prefix)
	if insinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])

main()
