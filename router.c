#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"


#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x806
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

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
// struct route_table_entry *get_best_route(uint32_t ip_dest, int left, int right) {
// 	/* TODO 2.2: Implement the LPM algorithm */
// 	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
// 	 * the rtable are in network order already */
// 	for (int i = 0; i < rtable_len; i++) {
// 		if (rtable[i].prefix == (ip_dest & rtable[i].mask)) {
// 			return &rtable[i];
// 		}
// 	}
// 	return NULL;

// 	// if (left >= right) {
// 	// 	return NULL;
// 	// }

// 	// int mid = (left + right) / 2;
// 	// if (rtable[mid].prefix == (ip_dest & rtable[mid].mask)) {
// 	// 	// return get_biggest_mask();
// 	// 	return &rtable[mid];
// 	// }

// 	// if (rtable[mid].prefix < (ip_dest & rtable[mid].mask)) {
// 	// 	return get_best_route(ip_dest, mid + 1, right);
// 	// } else {
// 	// 	return get_best_route(ip_dest, left, mid - 1);
// 	// }


// }

struct route_table_entry *get_best_route(uint32_t ip_dest, int left, int right, struct route_table_entry *best_so_far)
{
	if (left > right) {
		return best_so_far;
	}

	int mid = (left + right) / 2;

	if ((ip_dest & rtable[mid].mask) == rtable[mid].prefix) {
		if (best_so_far) {
			if (ntohl(rtable[mid].mask) > ntohl(best_so_far->mask)) {
				best_so_far = &rtable[mid];
			}
		} else {
			best_so_far = &rtable[mid];
		}
	}

	if (ntohl(ip_dest) < ntohl(rtable[mid].prefix)) {
			return get_best_route(ip_dest, left, mid - 1, best_so_far);
		} else {
			return get_best_route(ip_dest, mid + 1, right, best_so_far);
		}
}

int compare_ips(const void *r1, const void *r2)
{
	struct route_table_entry *route1 = (struct route_table_entry *)r1;
	struct route_table_entry *route2 = (struct route_table_entry *)r2;

	if (!(ntohl(route1->prefix) - ntohl(route2->prefix))) {
		return (ntohl(route1->mask) - ntohl(route2->mask));
	}
	return ntohl(route1->prefix) - ntohl(route2->prefix);

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

// int compare_masks(const void *r1, const void *r2)
// {
// 	struct route_table_entry route1, route2;

// 	route1 = *(struct route_table_entry *)r1;
// 	route2 = *(struct route_table_entry *)r2;
	

// 	return route2.mask - route1.mask;
// }

// int compare_ips(const void *r1, const void *r2)
// {
// 	struct route_table_entry route1, route2;

// 	route1 = *(struct route_table_entry *)r1;
// 	route2 = *(struct route_table_entry *)r2;
	

// 	return route1.prefix - route2.prefix;
// }

// struct route_table_entry *get_best_route(uint32_t ip_dest) {
// 	/* Implement the LPM algorithm */

// 	//I use binary search to find the best route

// 	int left = 0;
// 	int right = rtable_len - 1;
// 	int mid = (left + right) / 2;

// 	struct route_table_entry *best_route = NULL;

// 	while (left <= right) {

// 		//I sort descending by prefix
// 		//If the prefixes match, I sort descending by mask
// 		if ((ip_dest & rtable[mid].mask) == rtable[mid].prefix) {
// 			if (best_route != NULL) {
// 				if (ntohl(rtable[mid].mask) > ntohl(best_route->mask)) {
// 					best_route = &rtable[mid];
// 				}
// 			}


// 			if (best_route == NULL) {
// 				best_route = &rtable[mid];
// 			}
// 		}
		
// 		if (ntohl(rtable[mid].prefix) < ntohl(ip_dest)) {
// 			left = mid + 1;
// 		} else {
// 			right = mid - 1;
// 		}

// 		mid = (left + right) / 2;
// 	}

// 	return best_route;
// }

// int compare_rtable(const void *a, const void *b) {

// 	const struct route_table_entry *entry_a = (struct route_table_entry *)a;
// 	const struct route_table_entry *entry_b = (struct route_table_entry *)b;

// 	// Sort by prefix in descending order
	
// 	if (ntohl(entry_a->prefix) < ntohl(entry_b->prefix)) {
// 		return -1;
// 	}

// 	if (ntohl(entry_a->prefix) > ntohl(entry_b->prefix)) {
// 		return 1;
// 	}

// 	// Sort by mask in descending order

// 	if (ntohl (entry_a->mask) < ntohl(entry_b->mask)) {
// 		return -1;
// 	} else 

// 	if (ntohl (entry_a->mask) > ntohl(entry_b->mask))
// 		return 1;
// 	else 

// 	// The routes are equal
// 	return 0;
// }

char *create_icmp(struct ether_header *eth_hdr, struct iphdr *ip_hdr, uint8_t type, char *payload, ssize_t len)
{
	struct icmphdr *header = malloc(sizeof(struct icmphdr));
	char *buf = malloc(sizeof(struct icmphdr) + sizeof(struct iphdr) + 64);
	header->checksum = 0;
	header->type = type;
	header->code = 0;
	header->un.echo.id = 0;
	header->un.echo.sequence = 0;

	memcpy((void *)buf, (const void *)header, sizeof(struct icmphdr));
	memcpy((void *)(buf + sizeof(struct icmphdr)), (const void *)ip_hdr, sizeof(struct iphdr));
	memcpy((void *)(buf + sizeof(struct icmphdr) + sizeof(struct iphdr)), (const void *)payload, 64);


	header->checksum = htons(checksum((uint16_t *)buf, len));
	return buf;
}

char *create_ip_hdr(char *interface_ip, uint32_t daddr)
{
	struct iphdr *header = malloc(sizeof(struct iphdr));
	header->ihl = 5;
	header->version = 4;
	header->tos = 0;
	header->tot_len = htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 64);
	header->id = htons(1);
	header->frag_off = 0;
	header->ttl = 100;
	header->protocol = 1; //we don't care
	header->saddr = inet_addr(interface_ip);
	header->daddr = daddr;
	
	
	header->check = 0;
	header->check = htons(checksum((uint16_t *)header, sizeof(struct iphdr)));
	return (char *)header;


}

char *create_eth_hdr(int interface, struct ether_header *eth_hdr)
{
	struct ether_header *header = malloc(sizeof(struct ether_header));
	header->ether_type = htons(ETHERTYPE_IP);
	// header->ether_shost[] = get_interface_mac();

	get_interface_mac(interface, header->ether_shost);
	memcpy((void *)header->ether_dhost, (const void *)eth_hdr->ether_shost, 6 * sizeof(uint8_t));
	return (char *)header;
}

void send_icmp(struct ether_header *eth_hdr, struct iphdr *ip_hdr,
uint8_t type, char *buf, ssize_t len, int interface)
{
	ssize_t bufsize = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
	char *new_buf = malloc(bufsize);
	char *payload = buf + sizeof(struct ether_header) + sizeof(struct iphdr);
	char *icmp = create_icmp(eth_hdr, ip_hdr, type, payload, len);
	ssize_t icmp_size = sizeof(struct icmphdr) + sizeof(struct iphdr) + 64;
	char *first_ipv4 = create_ip_hdr(get_interface_ip(interface), ip_hdr->saddr);
	char *new_eth_hdr = create_eth_hdr(interface, eth_hdr);
	char *copy_addr = new_buf;
	memcpy((void *)copy_addr, (const void *)new_eth_hdr, sizeof(struct ether_header));
	copy_addr += sizeof(struct ether_header);
	memcpy((void *)copy_addr, (const void *)first_ipv4, sizeof(struct iphdr));
	copy_addr += sizeof(struct iphdr);
	memcpy((void *)copy_addr, (const void *)icmp, icmp_size);
	send_to_link(interface, new_buf, bufsize);
}

void icmp_reply(char *buf, int interface, ssize_t len)
{
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	uint8_t aux[6];
	memcpy((void *)aux, (const void *)(eth_hdr->ether_dhost), 6);
	memcpy((void *)(eth_hdr->ether_dhost), (const void *)(eth_hdr->ether_shost), 6);
	memcpy((void *)eth_hdr->ether_shost, (const void *)aux, 6);

	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));


	icmp_hdr->type = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum =
		htons(checksum((uint16_t *)icmp_hdr,
					   len - sizeof(struct ether_header)) -
					   sizeof(struct iphdr));

	send_to_link(interface, buf, len);

	
}



// void send_arp_request(struct route_table_entry *best_route, int interface)
// {
	

// 	int len = sizeof(struct ether_header) + sizeof(struct arp_header);
// 	char *buf = malloc(len);
// 	struct ether_header *eth_hdr = (struct ether_header *)buf;
// 	struct arp_header *arp_hdr =
// 		(struct arp_header *)(buf + sizeof(struct ether_header));

// 	// if (inet_addr(get_interface_ip(interface)) != arp_hdr->tpa) {
// 	// 	return;
// 	// }

// 	char *alpha_mac = "ff:ff:ff:ff:ff:ff";
// 	hwaddr_aton(alpha_mac, eth_hdr->ether_dhost);
// 	get_interface_mac(best_route->interface, eth_hdr->ether_shost);
// 	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

// 	arp_hdr->htype = htons(1);
// 	arp_hdr->ptype = htons(ETHERTYPE_IP);
// 	arp_hdr->hlen = 6;
// 	arp_hdr->plen = 4;
// 	arp_hdr->op = htons(1);
// 	arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
// 	arp_hdr->tpa = best_route->next_hop;
// 	get_interface_mac(best_route->interface, arp_hdr->sha);
// 	char *zero_mac = "00:00:00:00:00:00";
// 	hwaddr_aton(zero_mac, arp_hdr->tha);

// 	send_to_link(best_route->interface, buf, len);
// }

// struct arp_header {
// 	uint16_t htype;   /* Format of hardware address */
// 	uint16_t ptype;   /* Format of protocol address */
// 	uint8_t hlen;    /* Length of hardware address */
// 	uint8_t plen;    /* Length of protocol address */
// 	uint16_t op;    /* ARP opcode (command) */
// 	uint8_t sha[6];  /* Sender hardware address */
// 	uint32_t spa;   /* Sender IP address */
// 	uint8_t tha[6];  /* Target hardware address */
// 	uint32_t tpa;   /* Target IP address */
// } __attribute__((packed));

struct arp_header *get_arp_hdr(struct route_table_entry *best_route, uint16_t op, struct arp_header *old_arp,
									uint8_t *hw)
{
	struct arp_header *new_arp = malloc(sizeof(struct arp_header));
	new_arp->htype = htons(1);
	new_arp->ptype = htons(ETHERTYPE_IP);
	new_arp->hlen = 6;
	new_arp->plen = 4;
	new_arp->op = htons(op);
	if (op == 1) {
		get_interface_mac(best_route->interface, new_arp->sha);
		new_arp->spa = inet_addr(get_interface_ip(best_route->interface));
		hwaddr_aton("00:00:00:00:00:00", new_arp->tha);
		new_arp->tpa = best_route->next_hop;
	} else if (op == 2) {
		memcpy(new_arp->tha, old_arp->sha, 6);
		memcpy(new_arp->sha, hw, 6);
		
		new_arp->spa = old_arp->tpa;
		new_arp->tpa = old_arp->spa;
		
		
	} else {
		perror("Wrong arp_op_code\n");
	}
	

	return new_arp;
}

void arp_request(struct route_table_entry *best_route)
{
	char *buf = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	// struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	hwaddr_aton("ff:ff:ff:ff:ff:ff", eth_hdr->ether_dhost);
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	// (buf + sizeof(struct ether_header)) = (char *)get_arp_hdr(best_route);
	memcpy((void *)(buf + sizeof(struct ether_header)), (const void *)get_arp_hdr(best_route, ARP_OP_REQUEST, NULL, NULL), sizeof(struct arp_header));

	send_to_link(best_route->interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
}



// void send_arp_reply(char *buf, int len, struct arp_table_entry *mac_table,
// 					int interface, int *mac_table_len)
// {
// 	struct ether_header *eth_hdr = (struct ether_header *)buf;
// 	struct arp_header *arp_hdr =
// 		(struct arp_header *)(buf + sizeof(struct ether_header));

// 	uint8_t mac[6];
// 	get_interface_mac(interface, mac);
// 	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
// 	memcpy(eth_hdr->ether_shost, mac, 6);

// 	arp_hdr->op = htons(2);
// 	uint32_t aux = arp_hdr->spa;
// 	arp_hdr->spa = arp_hdr->tpa;
// 	arp_hdr->tpa = aux;

// 	memcpy(arp_hdr->tha, arp_hdr->sha, 6);
// 	memcpy(arp_hdr->sha, mac, 6);

// 	send_to_link(interface, buf, len);
// }

void arp_reply(char *buf, int interface)
{
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	uint8_t hw[6];
	get_interface_mac(interface, hw);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, hw, 6);
	memcpy((void *)(buf + sizeof(struct ether_header)), (const void *)get_arp_hdr(NULL, ARP_OP_REPLY, (struct arp_header *)(buf + sizeof(struct ether_header)), hw), sizeof(struct arp_header));
	send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
}

void update_arp_table(char *buf)
{
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	struct arp_table_entry new_ent;
	new_ent.ip = arp_hdr->spa;
	memcpy((void *)new_ent.mac, (const void *)arp_hdr->sha, 6);
	arp_table[arp_table_len] = new_ent;
	arp_table_len++;
}

void send_queue(queue q, char *buf, int interface)
{
	printf("DEQUEUE\n");
	char *old_buf = (char *)queue_deq(q);
	struct iphdr *old_ip = (struct iphdr *)(old_buf + sizeof(struct ether_header));
	struct ether_header *old_eth = (struct ether_header *)old_buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	// struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// struct route_table_entry *route = get_best_route(ip_hdr->daddr);

	memcpy((void *)old_eth->ether_shost, (const void *)arp_hdr->tha, 6);
	memcpy((void *)old_eth->ether_dhost, arp_hdr->sha, 6);

	////////////////////////////////////////////////////////////////////////
	// nu sunt sigur daca interfata e buna
	////////////////////////////////////////////////////////////////////////
	ssize_t len = sizeof(struct ether_header) + ntohs(old_ip->tot_len);
	send_to_link(interface, old_buf, len);
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


	// arp_table_len = parse_arp_table( "arp_table.txt", arp_table);

	queue q = queue_create();

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_ips);
	
	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be converted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		

		/* Check if we got an IPv4 packet */
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			printf("arp_mare\n");

			printf("op = %hu\n", arp_hdr->op);


			if (ntohs(arp_hdr->op) == 2) {
				printf("arp_reply\n");
				update_arp_table(buf);
				if (!queue_empty(q)) {
					send_queue(q, buf, interface);
				}
				continue;
			} else if (ntohs(arp_hdr->op) == 1) {
				printf("arp_request\n");
				arp_reply(buf, interface);
				// send_arp_reply(buf, len, arp_table, interface, &arp_table_len);
				continue;
			} else {
				printf("arp_prost\n");
				continue;
			}
		}

		/* TODO 2.1: Check the ip_hdr integrity using ip_checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) */
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		uint16_t csum = ip_hdr->check;
		ip_hdr->check = 0;
		uint16_t calculated_checksum = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		
		if (csum != calculated_checksum) {
			printf("Checksum failed\n");
			continue;
		}

		ip_hdr->check = csum;

		//echo ICMP

		if (ip_hdr->protocol == 1 && ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
			if (icmp_hdr->type == 8) {
				icmp_reply(buf, interface, len);
				continue;
			}
		}

		/* TODO 2.2: Call get_best_route to find the most specific route, continue; (drop) if null */
		struct route_table_entry *route = get_best_route(ip_hdr->daddr, 0, rtable_len - 1, NULL);
		// route.

		uint8_t icmp_type;

		if (!route) {
			printf("Destination unreachable\n");
			icmp_type = 3;
			send_icmp(eth_hdr, ip_hdr, icmp_type, buf, len, interface);
			continue;
		}
		/* TODO 2.3: Check TTL >= 1. Update TLL. Update checksum  */
		if (ip_hdr->ttl <= 1) {
			printf("TTL < 1\n");
			icmp_type = 11;
			send_icmp(eth_hdr, ip_hdr, icmp_type, buf, len, interface);
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

		// get_interface_mac()
		
		
		

		if (!ret2) {
			printf("enqueue\n");

			char *old_buf = malloc(len);
			memcpy((void *)old_buf, (const void *)buf, len);

			
			queue_enq(q, (void *)old_buf);
			arp_request(route);
			// send_arp_request(route, interface);

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