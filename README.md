# simple-router

Function Descriptions
---------------------

sr_router.c
--------------------

void sr_init(struct sr_instance* sr)
- This method initializes the sr instance and all its member variables.

struct sr_rt * long_pref_match(struct sr_instance* sr,
        uint32_t ip_dst)

- This method is called when the router determines the packet received is not for any of its interfaces and it needs to find the next hop entry from the routing table.
- This function uses Longest Prefix Match to determine the next hop entry which works as follows:
- The function loops over all entries in the routing table and calculates the destination network using the netmask              and then applies the same netmask to the destination IP address and checks if they're equal.
- If they are, it stores a pointer to the rt entry and records the prefix length which is just the number of 1s in the           binary representation of the netmask.
- Finally, the pointer to the entry with the maximum prefix length is returned as the next hop entry.
- If no entry is matched, the function returns NULL.

void *create_arp_request(struct sr_instance* sr,
        uint32_t target_ip,
        uint8_t * packet,
        unsigned int len,
        char* iface)

- This method is called when the router a packet that is not intended for itself but for a host contained in the router's routing table.
- The router must now send an ARP request to determine the next-hop MAC address and then forward the packet.
- This method creates an packet buffer then creates packets in the order: Ethernet, ARP.
- Once a request is sent over the LAN, it is stored in the ARP cache and repeatedly sent till timeout or arp reply.
- The packet argument along with len refers to the packet received for which we need to send an ARP request before we can forward the packet.
- This packet is added to the ARP request queue as well, so it can be forwarded if/when the ARP reply is received.

void create_arp_reply(struct sr_instance* sr,
        sr_ethernet_hdr_t *ether_packet,
        sr_arp_hdr_t *arp_req,
        struct sr_if *if_walker)

- This method is called when the router receives an arp request and it has to send a reply back to the host who sent the ARP.
- This method creates a packet buffer and creates packets in the order: Ethernet, ARP.
- The address from the interface object is copied to the ethernet packet as the source address and sent.


void send_icmp_port_unreachable(struct sr_instance* sr,
        sr_ethernet_hdr_t *ether_packet,
        sr_ip_hdr_t *ip_packet,
        char* iface)

- This method is called when the router receives a TCP/UDP packet on one of its router interfaces.
- In that case, the router needs to reply with an icmp_port_unreachable as it doesn't service TCP/UDP ports.
- The method creates a packet buffer and creates packets in the order: Ethernet, IP, ICMP

void send_icmp_ttl_exceeded(struct sr_instance* sr,
        sr_ethernet_hdr_t *ether_packet,
        sr_ip_hdr_t *ip_packet,
        char* iface)

- This method is called when the ttl on an ip packet is decremeted to 0.
- This method sends an icmp ttl exceeded packet back to the host who sent the packet to the router.
- The method creates a packet buffer and creates packets in the order: Ethernet, IP, ICMP

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet
        unsigned int len,
        char* iface)

- This is the method that is called when a packet is received on one of the router's interfaces.
- First this method checks the type of packet: ARP or IP.
- If the type of packet is IP:
  - Sanitization checks:
    - Length check and checksum
  - Checks if packet is for the router or not:
  - If the packet is for the router:
    - send back an ICMP reply
  - If packet is not for router:
    - find destination in routing table
    - If destination in routing table:
      - send ARP request for target IP and add ip packet to list of packets waiting for ARP reply.
    - If destination is NOT in routing table:
      - send ICMP net unreachable back to source
- If the type of packet is ARP:
  - Sanitization checks: check packet length
  - Check if ARP request or reply:
  - If ARP request:
    - send ARP reply using create_arp_reply
  - If ARP reply:
    - forward all packets waiting on arp reply by loading corresponding arp request object.

---------------------------------------------------------------------------------------------------

sr_arpcache.c
-------------------

void send_icmp_host_unreachable(struct sr_instance *sr,
        struct sr_arpreq * req_walker)

- This method is called when a timeout occurs after a host hasn't responded to the router's ARP request.
- This method sends an icmp_host_unreachable packet back to the sender of the packets that are waiting on the ARP reply.
- This method loads all the pending packets, then for each packet, creates the icmp packet and sends it.
- This method creates a packet buffer then creates and copies packets in the order: Ethernet, IP, ICMP.

void sr_arpcache_sweepreqs(struct sr_instance *sr)

- This method gets called every second.
- For every ARP request we send out, we want to check if a reply was received, and if not, we want to resend the ARP.
- It first loads all the ARP requests
- Then for each request, does the following...
- gets current time and checks if a second has passed since the last request was sent.
- if more than 5 requests have been sent:
  - send ICMP host unreachable message to source host
- else, send another ARP request.

---------------------------------------------------------------------------------------------------
