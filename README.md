# PandShark 
## Author: [Raphael Dray](https://www.linkedin.com/in/raphaeldray/)

PandShark is a tool designed to analyze/read pcap files.

It can parse from **PCAP** file format:

PandShark, in its minimal display, will always print:
* _Packet index_ (from the list of read packets)
* _IP/MAC address_
* _Protocol_
* _Packet Length_
* _Date_


* **ARP**
  * **Printed Fields**:
    * _ARP Info_ (i.e. Who has 24.166.175.220? Tell 69.76.216.1), useful for the comprehension.
* **DHCP**
  * _Printed Fields_:
    * _Message Type (Discover, Offer...)_, useful for understanding the request/response.
    * _Transaction ID_, useful for following the response/request.
* **DNS**
  * _Printed Fields_:
    * _DNS Query Type (i.e. Standard Query...)_, useful for understanding the type of the query.
    * _Query ID_, useful for following the response/request.
    * _Query Class_, useful for understanding the response needed to be given then.
    * _DNS Query Name_, useful for reading which server are we requesting.
      * For each **DNS Answers (A, AAAA, CNAME...)**:
        * Print the information about the answer
* **FTP**
  * _FTP Message with indication about Request/Response_, useful for reading the message sent and received.
* **HTTP**
  * _HTTP Message split on CRLF_, useful for reading the message sent and received.
* **ICMP**
  * **Printed Fields**:
    * _Type/Code Combination (i.e. Echo Reply/Echo Request)_, useful for determining the purpose of the ICMP packet.
    * _ID_, useful since the ID could reference in certain cases the PID of the process sending the packet.
    * _Sequence Number_, useful in order to determine if we lost packets.
    * _Time To Live_, useful in case you want to fingerprint the OS of the sender/receiver (**From IPV4**).
* **ETHERNET**
* **TCP**
* **UDP**
* **IPV4**

In its verbose mode (_display nth_), every protocol header about a specific 
packet and all their info are printed to visualize all fields.

Moreover, it includes a [protocol detection system](https://github.com/MrrRaph/PandShark/blob/master/src/core/headers/layer4/ProtocolDetector.java) 
in order to detect protocols encapsulated into TCP/UDP frames.

It includes also some PCAP samples to test different protocol detections.

## Installation:
You'll need to have Java 17 with preview enabled to run this program (--enable-preview).

Clone this repository:
```bash
git clone git@github.com:MrrRaph/PandShark.git
```

Then run the main class **PcapReader** in src.core.PcapReader.

## Usage:
Give a pcap as an argument to PandShark.

PandShark give you a prompt in order to navigate through the packets:
```
1426 packets read
PandShark >> display
1	10.0.4.46 -> 8.8.8.8	DNS 92 Standard Query 0x9200 A google.fr
2	8.8.8.8 -> 10.0.4.46	DNS 96 Standard Query 0x9200 A google.fr A Address: 142.250.201.163
3	08:00:27:43:73:BC -> 00:00:00:00:00:00	 ARP 42 Who has 10.0.4.254? Tell 10.0.4.46
4	00:26:55:E6:02:A0 -> 08:00:27:43:73:BC	 ARP 60 10.0.4.254 is at 00:26:55:E6:02:A0
5	00:26:55:E6:02:A0 -> 00:00:00:00:00:00	 ARP 60 Who has 10.0.4.46? Tell 10.0.4.254
6	08:00:27:43:73:BC -> 00:26:55:E6:02:A0	 ARP 42 10.0.4.46 is at 08:00:27:43:73:BC
7	08:00:27:AC:C2:F6 -> FF:FF:FF:FF:FF:FF	 ARP 60 Who has 10.0.4.27? Tell 0.0.0.0
8	08:00:27:AC:C2:F6 -> FF:FF:FF:FF:FF:FF	 ARP 60 Who has 10.0.4.27? Tell 0.0.0.0
9	10.0.4.46 -> 8.8.8.8	DNS 72 Standard Query 0xFA49 A whois.nic.fr
10	10.0.4.46 -> 8.8.8.8	DNS 72 Standard Query 0xB04A AAAA whois.nic.fr
...

PandShark >> display 10
Frame 10: 72 bytes on wire (576 bits)
	Encapsulation type: Ethernet (1)
** Ethernet Header **
	Destination IP: 00:26:55:E6:02:A0
	Source IP: 08:00:27:43:73:BC
	EtherType: 0x0800 (IPv4)
** IPv4 Header **
	IP version: IPv4
	IHL: 20 bytes
	Service: 0x00
	Total Length: 58 bytes
	Identification: 42947
	Flags:
		Don't Fragment: false
		More Fragment: false
	Position Fragment: 16384
	TTL: 64
	Protocol: UDP
	Checksum: 0x74B2
	Source IP: 10.0.4.46
	Destination IP: 8.8.8.8
** UDP Header **
	Source Port: 51451
	Destination Port: 53
	Length: 38
	Checksum: 0x1E75
** DNS Header **
	Transaction ID = 0xB04A
	Flags = 
		Response = Query
		Opcode = Standard Query
		Truncated = false
		Recursion Desired = true
		Z = 0
		Rcode = No Error
	Questions = 1
	Answer RRs = 0
	Authority RRs = 0
	Additional RRs = 0
	** Query N°1 **
		Name = whois.nic.fr
Type = IPv6 Address (AAAA)
Class = Internet (IN)
```

You can invoke the help command:
```
PandShark >> help
display [frameNumber]	Display all the packets read or the nth packets
help	Display this help prompt
exit	Quit the program
```