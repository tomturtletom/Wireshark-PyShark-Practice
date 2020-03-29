# PyShark/Wireshark Practice - March 27, 2020


import sys
import socket
import pyshark
import time
from collections import defaultdict


def getIPs(domains: [str]) -> (dict, list):
	# Returns a dictionary with the key representing the domain name, and the value representing a list of that domain's IP addresses.
	# Also returns a list of all of the combined IP addresses for the purpose of creating an IP filter for the capture.

	domain_ips = {}
	ips = []

	for domain in domains:
		ip_list = socket.gethostbyname_ex(domain)[-1]

		domain_ips[domain] = ip_list
		ips.extend(ip_list)

	return domain_ips, ips


def formatIPs(ips: list) -> str:
	# Returns a formatted string in the form: 'host (ip1 || ip2 || ...)' to be used as an argument for pysharks.LiveCapture's bpf_filter argument.
	
	formatted = 'host ('

	for ip in ips[:-1]:
		formatted += ip + ' || '

	formatted += ips[-1] + ')'
	return formatted


def getIPLengths(interface: str, filters: str, ips: list, max_time: int) -> dict:
	# Uses pyshark to capture the packets going through the specified interface with the given IP filter. Once the capture has concluded after waiting
	# for the specified amount of time, it will then loop through the capture and update the count of the number of packets and count of the byte length
	# for each IP in the filter. The byte length does include the packet header. It stores and returns this in a dictionary of a dictionary in the form:
	# 	returned = {<IP address>: {'length': <number of bytes>, 'num_of_pacs': <number of packets>}}

	capture = pyshark.LiveCapture(interface=interface, bpf_filter=filters)
	capture.sniff(timeout=max_time)
	time.sleep(max_time)
	capture.close()

	ip_lengths = defaultdict(lambda: defaultdict(int))

	for pac in capture[:len(capture)]:
		source = pac.ip.src
		dest = pac.ip.dst

		if source in ips:
			ip_lengths[source]['length'] += int(pac.ip.len)
			ip_lengths[source]['num_of_pacs'] += 1
		elif dest in ips:
			ip_lengths[dest]['length'] += int(pac.ip.len)
			ip_lengths[dest]['num_of_pacs'] += 1

	return ip_lengths


def displayAll(domain_info: dict, ip_info: dict, max_time: int):
	# Displays all of the collected information with columns: domain, IP address, number of packets, and number of bytes for each unique ip address. Also
	# displays the total number of packets and bytes at the end with projections over a day and a month.

	in_day = int(86400 / max_time)
	in_month = int(in_day * 30)

	total_pacs = 0
	total_bytes = 0

	print('\n{:35}{:35}{:35}{:35}'.format('DOMAIN', 'IP ADDRESS', 'NUMBER OF PACKETS', 'NUMBER OF BYTES'))

	for domain, ip_list in domain_info.items():
		for ip in ip_list:
			pacs = ip_info[ip]['num_of_pacs']
			length = ip_info[ip]['length']

			if pacs != 0:
				print('{:35}{:35}{:<35}{:<35}'.format(domain, ip, pacs, length))
				total_pacs += pacs
				total_bytes += length

	print('\n{:<25} {} bytes ({} packets)'.format('TOTAL OVER ' + str(max_time) + ' SECONDS:', total_bytes, total_pacs))
	print('{:<25} {} bytes ({} packets)'.format('PROJECTED OVER 1 DAY:', total_bytes * in_day, total_pacs * in_day))
	print('{:<25} {} bytes ({} packets)'.format('PROJECTED OVER 30 DAYS:', total_bytes * in_month, total_pacs * in_month))


def main():
	interface = sys.argv[1]
	domains_file_name = sys.argv[2]
	time_capture = int(sys.argv[3])

	fp = open(domains_file_name, 'r')

	domains = fp.read().splitlines()
	domain_info, ip_filter = getIPs(domains)

	formatted_ips = formatIPs(ip_filter)
	ip_info = getIPLengths(interface, formatted_ips, ip_filter, time_capture)
	displayAll(domain_info, ip_info, time_capture)


if __name__ == "__main__":
    main()