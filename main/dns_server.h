#ifndef __DNA_SERVER_H__
#define __DNA_SERVER_H__

void dns_server_send(void);
void get_dns_request(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
void my_udp_init(void);

#endif