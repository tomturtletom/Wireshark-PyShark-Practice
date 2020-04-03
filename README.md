# Wireshark-PyShark-Practice
This project is to practice using the PyShark wrapper to capture live packet information on a specified interface for a specific amount of time. IP filters can be used so that the program will only capture packets with either a source or destination in the domain file to filter out and display relevant packets. Upon program completion, the console will print each unique IP address, along with its domain name, the total packet count, and total packet size for that IP. After each line corresponding to each unique IP is printed, the console will display the combined totals for that time period along with the projected amounts for 1 day and 30 days.

The program requires Wireshark to be installed on the device, and can be run in the command line with 3 arguments:  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;>>> python capture_info.py \<interface> \<domain_file> \<seconds>  

\<interface>: The interface on which to capture  
\<domain_file>: A .txt file with a domain on each line that represents the relevant IP addresses to capture  
\<seconds>: The amount of time, in seconds, that the capture should run

Sample Input:
>python capture_info.py Wi-Fi domains.txt 30

Sample Output (Domains do not correlate to IP addresses in this sample):
DOMAIN                                  IP ADDRESS               NUMBER OF PACKETS        NUMBER OF BYTES
sdnsagent.brightcloud.com               192.168.0.243            13                       1794
dnspds.brightcloud.com                  192.168.0.1              18                       1672
dnspds.brightcloud.com                  192.168.0.217            1                        203
sdnsp.brightcloud.com                   239.255.255.250          20                       3457
sdnsp.brightcloud.com                   224.0.0.251              14                       1009
dnspds.s3.amazonaws.com                 192.168.0.148            8                        551

TOTAL OVER 30 SECONDS:    8686 bytes (74 packets)
PROJECTED OVER 1 DAY:     25015680 bytes (213120 packets)
PROJECTED OVER 30 DAYS:   750470400 bytes (6393600 packets)
