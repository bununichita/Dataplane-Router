#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"


#define ETHERTYPE_IP 0x0800

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *arp_table;
int arp_table_len;

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	/* TODO 2.2: Implement the LPM algorithm */
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
	 * the rtable are in network order already */
	for (int i = 0; i < rtable_len; i++) {
		if (rtable[i].prefix == (ip_dest & rtable[i].mask)) {
			return &rtable[i];
		}
	}
	return NULL;
}

struct arp_table_entry *get_mac_entry(uint32_t given_ip) {
	/* TODO 2.4: Iterate through the MAC table and search for an entry
	 * that matches given_ip. */

	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}

	/* We can iterate thrpigh the arp_table for (int i = 0; i <
	 * arp_table_len; i++) */
	return NULL;
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_table_entry) * 100);
	DIE(arp_table == NULL, "memory");
	
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table( "arp_table.txt", arp_table);

	


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be converted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		/* Check if we got an IPv4 packet */
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}

		/* TODO 2.1: Check the ip_hdr integrity using ip_checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) */

		uint16_t csum = ip_hdr->check;
		ip_hdr->check = 0;
		uint16_t calculated_checksum = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		
		if (csum != calculated_checksum) {
			printf("Checksum failed\n");
			continue;
		}

		ip_hdr->check = csum;

		/* TODO 2.2: Call get_best_route to find the most specific route, continue; (drop) if null */
		struct route_table_entry *route = get_best_route(ip_hdr->daddr);
		if (!route) {
			printf("Destination unreachable\n");
			continue;
		}
		/* TODO 2.3: Check TTL >= 1. Update TLL. Update checksum  */
		if (ip_hdr->ttl < 1) {
			printf("TTL < 1\n");
			continue;
		}
		ip_hdr->ttl--;
		uint32_t next_hop = route->next_hop;
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		/* TODO 2.4: Update the ethernet addresses. Use get_mac_entry to find the destination MAC
		 * address. Use get_interface_mac(m.interface, uint8_t *mac) to
		 * find the mac address of our interface. */
		  
		struct arp_table_entry *ret2 = get_mac_entry(next_hop);
		
		
		

		if (!ret2) {
			printf("No MAC entry found\n");
			continue;
		}

		get_interface_mac(route->interface, eth_hdr->ether_shost);

		// for (int i = 0; i < 6; i++) {
		// 	eth_hdr->ether_shost[i] = mac[i];
		// 	eth_hdr->ether_dhost[i] = arp_table->mac[i];
		// }

		memcpy (eth_hdr->ether_dhost, ret2->mac, sizeof(ret2->mac));
		memcpy (eth_hdr->ether_shost, ret2->mac, sizeof(ret2->mac));

		send_to_link(route->interface, buf, len);

	}
}
