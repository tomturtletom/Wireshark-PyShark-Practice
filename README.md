# Wireshark-PyShark-Practice
This project is to practice using the PyShark wrapper to capture live packet information on a specified interface for a specific amount of time. IP filters can be used so that the program will only capture packets with either a source or destination in the domain file to filter out and display relevant packets. Upon program completion, the console will print each unique IP address, along with its domain name, the total packet count, and total packet size for that IP. After each line corresponding to each unique IP is printed, the console will display the combined totals for that time period along with the projected amounts for 1 day and 30 days.

The program requires Wireshark to be installed on the device, and can be run in the command line with 3 arguments:  
    >>> python capture_info.py <interface> <domain_file> <seconds>
  
<interface>: The interface on which to capture  
<domain_file>: A .txt file with a domain on each line that represents the relevant IP addresses to capture  
<seconds>: The amount of time, in seconds, that the capture run  
