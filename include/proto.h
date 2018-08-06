
#define A_INTERNAL_PKT_SIZE 2
#define A_INTERNAL_RESERVE_SIZE 2
#define A_INTERNAL_FD_SIZE 2
#define A_INTERNAL_PING_SEND_SIZE 2
#define A_INTERNAL_PACKET_TYPE 4
#define A_INTERNAL_PKT_IDX_SIZE 4
#define A_INTERNAL_HEADER (A_INTERNAL_PKT_SIZE+A_INTERNAL_RESERVE_SIZE+A_INTERNAL_FD_SIZE+A_INTERNAL_PING_SEND_SIZE+A_INTERNAL_PACKET_TYPE+A_INTERNAL_PKT_IDX_SIZE)
#define A_INTERNAL_HEADER_REMOVE_A_INTERNAL_PKT_SIZE (A_INTERNAL_HEADER - A_INTERNAL_PKT_SIZE)

#define B_OPENVPN_PKT_SIZE 2
#define B_OPENVPN_KEYID_OPCODE 1
#define B_OPENVPN_PACKET_IDX 4
#define B_OPENVPN_PDATA_HEADER (B_OPENVPN_PKT_SIZE + B_OPENVPN_KEYID_OPCODE + B_OPENVPN_PACKET_IDX)
#define B_OPENVPN_PDATA_HEADER_REMOVE_B_OPENVPN_PKT_SIZE (B_OPENVPN_PDATA_HEADER - B_OPENVPN_PKT_SIZE)

#define PING_DATA_SIZE 16


#define OPENVPN_ETH_ALEN 6            /* ethernet address length */

struct openvpn_arp {
# define ARP_MAC_ADDR_TYPE 0x0001
	uint16_t mac_addr_type;       /* 0x0001 */
	uint16_t proto_addr_type;     /* 0x0800 */
	uint8_t  mac_addr_size;       /* 0x06 */
	uint8_t  proto_addr_size;     /* 0x04 */

# define ARP_REQUEST 0x0001
# define ARP_REPLY   0x0002
# define GARP_REQUEST 0x0003
# define GARP_REPLY   0x0004
	uint16_t arp_command;         /* 0x0001 for ARP request, 0x0002 for ARP reply */

	uint8_t   mac_src[OPENVPN_ETH_ALEN];
	char ip_src[4];
	//uint32_t ip_src;
	uint8_t   mac_dest[OPENVPN_ETH_ALEN];
	//uint32_t ip_dest;
	char ip_dest[4];
};

int process(struct epoll_ptr_data *epd,char *data,int len,char *out,int * out_len);
int get_opcode(char *x);
int get_keyid(char *x);
