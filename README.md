
# Dataplane Router

### Author: Nichita-Adrian Bunu, 323CA  Facultatea de Automatica si Calculatoare UNSTPB
**Contact:** [nichita_adrian.bunu@stud.acs.upb.ro](mailto:nichita_adrian.bunu@stud.acs.upb.ro)

---

## Overview

The program simulates the functionality of a router that supports IPv4, ICMP, and ARP protocols. The router waits for incoming packets (`recv_from_any_link()`), then processes them accordingly.

The routing tables for both routers are sorted by prefix, and if the prefixes are identical, by the mask. With sorted routing tables, the destination can be found using a binary search algorithm (`get_best_route()`).

At the start of the program, the ARP table is empty and will be populated using the ARP protocol.

---

## Processing Steps

1. **Extract the Ethernet Header**:  
   The program begins by extracting the Ethernet header from the packet.

2. **Handle ARP Packets**:  
   - If the Layer 3 packet type is ARP, the program checks whether it is an ARP REQUEST or REPLY.  
   - **For ARP REPLY**: An entry is added to the ARP table since the desired hardware address is found, and the packet destined for the found MAC address is sent.  
   - **For ARP REQUEST**: The program retrieves the requested hardware address (`get_interface_mac()`) and sends back a packet with the new information.

3. **Handle Non-ARP Packets**:  
   If the packet is not an ARP packet, the IP header is stored in "ip_hdr".

4. **Checksum Validation**:  
   The program checks for transmission errors using the checksum. If errors are detected, the packet is discarded.

5. **ICMP Handling**:  
   - If the IP packet contains an ICMP packet and the destination address matches the router's address, the router acknowledges it and notifies the originating router that the packet was discarded.

6. **Non-ICMP Packet Handling**:  
   - If there is no route to the destination, an ICMP packet with the type "Destination Unreachable" is sent.  
   - If the time-to-live (TTL) has reached 1, an ICMP packet with the type "Time Exceeded" is sent.

7. **Destination MAC Address Resolution**:  
   - If the destination hardware address for the current packet is unknown, the entire buffer is queued, and a broadcast is performed to obtain the address.

8. **Packet Forwarding**:  
   - If none of the above conditions are met, the packet is forwarded to the next hop.

---
