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

struct arp_table_entry *get_mac_entry(uint32_t given_ip)
{
	int i = 0;

	while(i++ < arp_table_len) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}

	return NULL;
}



char *create_icmp(struct ether_header *eth_hdr, struct iphdr *ip_hdr, uint8_t type, char *payload, ssize_t len)
{
	struct icmphdr *header = malloc(sizeof(struct icmphdr));
	char *buf = malloc(sizeof(struct icmphdr) + sizeof(struct iphdr) + 6);
	header->checksum = 0;
	header->type = type;
	header->code = 0;
	header->un.echo.id = 0;
	header->un.echo.sequence = 0;

	memcpy((void *)buf, (const void *)header, sizeof(struct icmphdr));
	memcpy((void *)(buf + sizeof(struct icmphdr)), (const void *)ip_hdr, sizeof(struct iphdr));
	memcpy((void *)(buf + sizeof(struct icmphdr) + sizeof(struct iphdr)), (const void *)payload, 6);


	header->checksum = htons(checksum((uint16_t *)buf, len));
	return buf;
}

char *create_ip_hdr(char *interface_ip, uint32_t daddr)
{
	struct iphdr *header = malloc(sizeof(struct iphdr));
	header->ihl = 5;
	header->version = 4;
	header->tos = 0;
	header->tot_len = htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 6);
	header->id = htons(1);
	header->frag_off = 0;
	header->ttl = 100;
	header->protocol = 1;
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
	get_interface_mac(interface, header->ether_shost);
	memcpy((void *)header->ether_dhost, (const void *)eth_hdr->ether_shost, 6 * sizeof(uint8_t));
	return (char *)header;
}

void send_icmp(struct ether_header *eth_hdr, struct iphdr *ip_hdr,
uint8_t type, char *buf, ssize_t len, int interface)
{
	// Pun cap la cap eth_hdr + ip_hdr + icmp_hdr + failed_ip_hdr + failed_payload
	ssize_t bufsize = sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 6;
	char *new_buf = malloc(bufsize);
	char *payload = buf + sizeof(struct ether_header) + sizeof(struct iphdr);
	char *icmp = create_icmp(eth_hdr, ip_hdr, type, payload, len);
	ssize_t icmp_size = sizeof(struct icmphdr) + sizeof(struct iphdr) + 6;
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
	icmp_hdr->checksum =htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 6));

	send_to_link(interface, buf, len);	
}


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
		int aux = 0;
		short aux2 = 0;
		memcpy((void *)new_arp->tha, (const void *)(&aux), sizeof(int));
		memcpy((void *)(new_arp->tha + sizeof(int)), (const void *)(&aux2), sizeof(short));
		new_arp->tpa = best_route->next_hop;
	} else if (op == 2) {
		memcpy(new_arp->tha, old_arp->sha, 6);
		memcpy(new_arp->sha, hw, 6);		
		new_arp->spa = old_arp->tpa;
		new_arp->tpa = old_arp->spa;		
	} else {
		perror("Wrong arp_op_code\n");
		return NULL;
	}
	return new_arp;
}

void arp_request(struct route_table_entry *best_route)
{
	char *buf = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	int aux = -1;
	short aux2 = -1;
	memcpy((void *)eth_hdr->ether_dhost, (const void *)(&aux), sizeof(int));
	memcpy((void *)(eth_hdr->ether_dhost + sizeof(int)), (const void *)(&aux2), sizeof(short));
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	memcpy((void *)(buf + sizeof(struct ether_header)),
			(const void *)get_arp_hdr(best_route, ARP_OP_REQUEST, NULL, NULL),
			sizeof(struct arp_header));

	send_to_link(best_route->interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
}


void arp_reply(char *buf, int interface)
{
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	uint8_t hw[6];
	get_interface_mac(interface, hw);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, hw, 6);
	memcpy((void *)(buf + sizeof(struct ether_header)),
			(const void *)get_arp_hdr(NULL, ARP_OP_REPLY,(struct arp_header *)(buf + sizeof(struct ether_header)), hw),
			sizeof(struct arp_header));
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
	char *old_buf = (char *)queue_deq(q);
	struct iphdr *old_ip = (struct iphdr *)(old_buf + sizeof(struct ether_header));
	struct ether_header *old_eth = (struct ether_header *)old_buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	memcpy((void *)old_eth->ether_shost, (const void *)arp_hdr->tha, 6);
	memcpy((void *)old_eth->ether_dhost, arp_hdr->sha, 6);
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



	queue q = queue_create();

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_ips);
	
	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			if (ntohs(arp_hdr->op) == 2) {
				update_arp_table(buf);
				if (!queue_empty(q)) {
					send_queue(q, buf, interface);
				}
				continue;
			} else if (ntohs(arp_hdr->op) == 1) {
				arp_reply(buf, interface);
				continue;
			} else {
				// bad arp
				continue;
			}
		}
		
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		uint16_t csum = ip_hdr->check;
		ip_hdr->check = 0;
		uint16_t calculated_checksum = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		
		if (csum != calculated_checksum) {
			// checksum failed
			continue;
		}

		ip_hdr->check = csum;

		//echo ICMP
		if (ip_hdr->protocol == ARP_OP_REQUEST) {
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
				if (icmp_hdr->type == 8) {
					icmp_reply(buf, interface, len);
					continue;
				}
			}
		}

		struct route_table_entry *route = get_best_route(ip_hdr->daddr, 0, rtable_len - 1, NULL);

		uint8_t icmp_type;

		if (!route) {
			// Destination unreachable
			icmp_type = 3;
			send_icmp(eth_hdr, ip_hdr, icmp_type, buf, len, interface);
			continue;
		}
		if (ip_hdr->ttl <= 1) {
			// Time exceeded
			icmp_type = 11;
			send_icmp(eth_hdr, ip_hdr, icmp_type, buf, len, interface);
			continue;
		}
		ip_hdr->ttl--;
		uint32_t next_hop = route->next_hop;
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		  
		struct arp_table_entry *ret2 = get_mac_entry(next_hop);

		if (!ret2) {
			char *old_buf = malloc(len);
			memcpy((void *)old_buf, (const void *)buf, len);			
			queue_enq(q, (void *)old_buf);
			arp_request(route);
			continue;
		}

		get_interface_mac(route->interface, eth_hdr->ether_shost);
		memcpy (eth_hdr->ether_dhost, ret2->mac, sizeof(ret2->mac));
		memcpy (eth_hdr->ether_shost, ret2->mac, sizeof(ret2->mac));

		send_to_link(route->interface, buf, len);
	}
}
