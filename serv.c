#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <pcap.h>
#include <stddef.h>

double time_as_double(void);
typedef struct {
    int seq_no;
    int length;
    int remaining;
    char data[0];
} forward_desc_t;
typedef struct {
    uint32_t magic;      //  magic number, used to identify ptunnel packets.
    uint32_t dst_ip;     //  destination IP and port (used by proxy to figure
    uint32_t dst_port;   //  out where to tunnel to)
    uint32_t state;   //  current connection state; see constants above.
    uint32_t ack;        //  sequence number of last packet received from other end
    uint32_t data_len;   //  length of data buffer
    uint16_t seq_no;     //  sequence number of this packet
    uint16_t id_no;      //  id number, used to separate different tunnels from each other
    char data[0];    //  optional data buffer
} __attribute__ ((packed)) ping_tunnel_pkt_t;

typedef struct {
    uint8_t vers_ihl;
    uint8_t tos;
    uint16_t pkt_len;
    uint16_t id;
    uint16_t flags_frag_offset;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
    char data[0];
} __attribute__ ((packed)) ip_packet_t;

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t seq;
    char data[0];
} __attribute__ ((packed)) icmp_echo_packet_t;

void handle_packet(char *buf, int bytes, int is_pcap, 
        struct sockaddr_in *addr, int icmp_sock);


void print_statistics();

void log();


typedef struct {
    int bytes;
    struct pqueue_elem_t *next;
    char data[0];
} pqueut_elem_t;

typedef struct {
    pqueut_elem_t *head;
    pqueut_elem_t *tail;
    int elems;
} pqueue_t;

typedef struct {
    pcap_t *pcap_desc;
    struct bpf_program fp;
    uint32_t netp;
    uint32_t netmask;
    char *pcap_err_buf;
    char *pcap_data_buf;
    pqueue_t pkt_q;
} pcap_info_t;
    
typedef struct proxy_desc_s {
    int sock;
    int bytes;
    int should_remove;
    char *buf;
    uint16_t id_no;
    uint16_t icmp_id;
    uint16_t pkt_type;
    uint32_t state;
    uint32_t type_flag;
    uint32_t dst_ip;
    uint32_t dst_port;
    struct sockaddr_in dest_addr;
    struct proxy_desc_s *next;
    //TODO
} proxy_desc_t;

#define MAX_EVENTS (600)
proxy_desc_t *fdlist[MAX_EVENTS + 1];//用于通过fd反查proxy_desc_t，文件描述符操作系统公用，所以分开无意义
enum { 
    payload_size = 1024,
    icmp_echo_request = 8,
    icmp_echo_reply = 0,
    ip_header_size = 20,
    icmp_header_size = 8,
    icmp_receive_buf_len = (payload_size + ip_header_size 
            + icmp_header_size + sizeof(ping_tunnel_pkt_t)),
    pcap_buf_size = (   payload_size + ip_header_size + icmp_header_size
        + sizeof(ping_tunnel_pkt_t)+64  )  * 64,
    seq_expiry_tbl_length = 65536;
};
typedef struct serv_conf_s {
    uint32_t proxy_ip;//proxy's internet address
    int tcp_listen_port;
    int tcp_port;
    int serv_sock;
    double now;
    proxy_desc_t *tunnul_desc;
    char *pcap_device;
//    int max_tunnels;
} serv_conf;
proxy_desc_t *create_and_insert_proxy_desc(uint16_t id_no, uint16_t icmp_id, int sock, 
        struct sockaddr_in *addr, uint32_t dst_ip, uint32_t dst_port, 
        uint32_t init_state, uint32_t type);
forward_desc_t *create_fwd_desc(uint16_t seq_no, uint32_t data_len, char *data);


void handle_data(icmp_echo_packet_t *pkt, int total_len, forward_desc_t *ring[], int *await_send, int *insert_idx, uint16_t *next_expected_seq);
proxy_desc_t* create_and_insert_proxy_desc(uint16_t id_no, uint16_t icmp_id, int sock, struct sockaddr_in *addr, uint32_t dst_ip, uint32_t dst_port, uint32_t init_state, uint32_t type);

typedef int error_rv_t;

error_rv_t
pt_server(serv_conf *conf) 
{

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {log(); return -1;}
    int max_sock = sock;

    //the part of pcap START
    pcap_info_t pc;
    pc.pcap_err_buf = malloc(PCAP_ERRBUF_SIZE);
    pc.pcap_data_buf = malloc(pcap_buf_size);
    pc.pcap_desc = pcap_open_live(conf->pcap_device, pcap_buf_size, 
            0/*promiscous*/, 50/*ms*/, pc.pcap_err_buf);

    if (pc.pcap_desc) {
        pcap_lookupnet(conf->pcap_device, &pc.netp, &pc.netmask, pc.pcap_err_buf);
        char pcap_filter_program[] = "icmp";
        pcap_compile(pc.pcap_desc, &pc.fp, pcap_filter_program, 0, pc.netp);
        pcap_setfilter(pc.pcap_desc, &pc.fp);
    } 

    pc.pkt_q.head = 0;
    pc.pkt_q.tail = 0;
    pc.pkt_q.elems = 0;
    //the part of pcap END

    char *buf = malloc(icmp_receive_buf_len);
    log();

//BIIIIIIIIIIIG for-loop
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev;
    struct epoll_event events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

    for (;;) {

        proxy_desc_t *cur = conf->tunnul_desc;

        for (/*LINE136*/ ;cur; cur = cur->next) {
            if (cur->sock) {
                epoll_ctl(epfd, EPOLL_CTL_ADD, cur->sock, &ev);
                if (cur->sock >= max_sock) {max_sock = cur->sock + 1;}
            }
        }

        int timeout = 10000;
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, timeout);
        /*
        for (prev = 0, cur = conf->tunnul_desc; 
                cur && cur->sock; 
                cur = tmp)  
        */
        proxy_desc_t *tmp;
        proxy_desc_t *prev;

        if (cur->should_remove) {
            print_statistics();
            tmp = cur->next;
            remove_proxy_desc(cur, prev);
        }

        if (!nfds) { 
            continue;
        }//When timeout happens, just continue to next for-loop

        int n = 0;
        /*
        for (cur = conf->tunnul_desc, prev = NULL; cur && cur->sock; cur = tmp, n++) 
        */
/*            int fd_now = events[n].datacreate_and_insert_proxy_desc.fd;*/

        for (int n = 0; n < nfds; n++) {
            if (events[n].data.fd == sock) {//TODO:需要将fd与cur一一映射起来，而不是O(n)搜索
                socklen_t addr_len = sizeof(struct sockaddr);
                struct sockaddr_in addr;
                ssize_t bytes = recvfrom(sock, buf, icmp_receive_buf_len, 
                        0, (struct sockaddr *)&addr, &addr_len);
                log();
                handle_packet(buf, bytes, 0, &addr, sock);
            } 

            if (events[n].data.fd < max_sock) {
                proxy_desc_t *cur = fdlist[events[n].data.fd];
                ssize_t bytes = recv(cur->sock, cur->buf, tcp_receive_buf_len, 0);
                if (bytes <= 0) {
                    log();
                    tmp = cur->next;
                    send_termination_msg(cur, sock);
                    log();
                    remove_proxy_desc();
                    continue;
                }
                queue_packet(cur, bytes, 0, 0);
                //TODO
            }

        }
        conf->now = time_as_double();
        void find_no_activity_to_close();//TODO

        void send_waiting_packet();

        void resend_packet_requiring_resend();

        void send_explicit_ack();

        if (pcap_dispatch(pc.pcap_desc, 32, pcap_packet_handler, 
                    (u_char *)&pc.pkt_q) > 0) {
            pqueut_elem_t *cur;
            struct sockaddr_in addr;

            while (pc.pkt_q.head) {
                cur = pc.pkt_q.head;
                memset(&addr, 0, sizeof(struct sockaddr));
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = *(in_addr_t *)&(((ip_packet_t *)(cur->data))->src_ip);
                handle_packet();
                pc.pkt_q.head = cur->next;
                free(cur);
                pc.pkt_q.elems--;
            }
            pc.pkt_q.tail = 0;
            pc.pkt_q.head = 0;
        }

    }
    
            

}


proxy_desc_t *create_and_insert_proxy_desc(uint16_t id_no, uint16_t icmp_id, int sock, struct sockaddr_in *addr, uint32_t dst_ip, uint32_t dst_port, uint32_t init_state, uint32_t type)
{
    proxy_desc_t *cur = calloc(1, sizeof(proxy_desc_t));
    cur->id_no = id_no;
    cur->dest_addr = *addr;
    cur->dst_ip = dst_ip;
    cur->dst_port = dst_port;
    cur->icmp_id = icmp_id;
    
    if (!sock) {
        cur->sock = socket(AF_INET, SOCK_STREAM, 0);
        memset(addr, 0, sizeof(struct sockaddr_in));
        addr->sin_port = htons((uint16_t)dst_port);
        addr->sin_addr.s_addr = dst_ip;
        addr->sin_family = AF_INET;
        connect(cur->sock, (struct sockaddr *)addr, sizeof(struct sockaddr_in) );
        log();
    } else {
        cur->sock = sock;
    }

    cur->state = init_state;
    cur->type_flag = type;
    cur->pkt_type = kICMP_echo_replay;//proxy
    cur->buf = malloc(icmp_receive_buf_len);
    cur->last_activity = time_as_double();
    //don't use linked list
    //TODO
    //insert_to_chain(cur);
    fdlist[id_no] = cur;//insert it to chain

    return cur;
}

void handle_data(icmp_echo_packet_t *pkt, int total_len, forward_desc_t *ring[], 
        int *await_send/*numbers*/, int *insert_idx,  uint16_t *next_expected_seq) {
{
    ping_tunnel_pkt_t *pt_pkt = (ping_tunnel_pkt_t *)pkt->data;
    int expected_len = sizeof(ip_packet_t) + sizeof(icmp_echo_packet_t) + sizeof(ping_tunnel_pkt_t);

    expected_len += pk_pkt->data_len;
    expected_len += expected_len % 2;

    if (total_len < expected_len) {
        //TODO NOT COMPLETELY received;
        //EXIT(0);
    } else {
            //TODO????
        if (pt_pkt->seq_no == *next_expected_seq) {//最先所等待的包到达
            if (!ring[*insert_idx]) {
                ring[*insert_idx] = create_fwd_desc(pt_pkt->seq_no, 
                        pt_pkt->data_len, pt_pkt->data);
                (*await_send)++;
                (*insert_idx)++;
            } else if (ring[*insert_idx]) {
                log();
            }

            (*next_expected_seq)++;
            if (*insert_idx >= kPing_window_size) { *insert_idx = 0; }

            while (ring[*insert_idx]) {
                if (ring[*insert_idx]->seq_no == *next_expected_seq) {
                    (*next_expected_seq)++;
                    (*insert_idx)++;
                    if (*insert_idx >= kPing_window_size)
                        *insert_idx = 0;
                } else {
                    break;
                }
            }
        } else {//后发包先到达
            int pos = -1;
            int old_or_wrapped_around = pt_pkt->seq_no - *next_expected_seq;
            if (old_or_wrapped_around < 0) {
                old_or_wrapped_around = 
                    (pt_pkt->seq_no + seq_expiry_tbl_length) - *next_expected_seq;
                if (old_or_wrapped_around < kPing_window_size) {//wrapped
                    pos = ((*insert_idx) + old_or_wrapped_around) % kPing_window_size;
                }
            } else if (old_or_wrapped_around < kPing_window_size) {
                pos = ((*insert_idx) + old_or_wrapped_around) % kPing_window_size;
            }

            if (pos != -1) {
                if (!ring[pos]) {
                    ring[pos] = create_fwd_desc(pt_pkt->seq_no, pt_pkt->data_len,
                            pt_pkt->data);
                    (*await_send)++;
                }
            }
                
        } 
    }


}

void handle_packet(char *buf, int bytes, int is_pcap,
        struct sockaddr_in *addr, int icmp_sock)
{
    if (bytes < sizeof(icmp_echo_packet_t) + sizeof(ping_tunnel_pkt_t)) {
       log(); 
    } else { 
        ip_packet_t *ip_pkt = buf;
        icmp_echo_packet_t *pkt = ip_pkt->data;
        ping_tunnel_pkt_t *pt_pkt = pkt->data;
        
        if (ntohl(pt_pkt->magic) == kPing_tunnel_magic) {
            pt_pkt->state = ntohl(pt_pkt->state);
            pkt->identifier = ntohs(pkt->identifier);
            pt_pkt->id_no = ntohs(pt_pkt->id_no);
            pt_pkt->seq_no = ntohs(pt_pkt->seq_no);
        } else {
            log();
            return ;
        }

        proxy_desc_t *cur = id_nolist[pt_pkt->id_no];
        if (cur) {
            uint32_t type_flag = cur->type_flag;
            if (type_flag == kProxy_flag) {
                cur->icmp_id = pkt->identifier;
            }
        } else {
            type_flag = kProxy_flag;
        }

        pkt_flag = pt_pkt->state & kFlag_mask;
        pt_pkt->state &= ~kFlag_mask;
        
        if (!cur && pkt_flag == kUser_flag && type_flag == kProxy_flag)  {
            pt_pkt->data_len = ntohl(pt_pkt->data_len);
            pt_pkt->ack = ntohl(pt_pkt->ack);
            gettimeofday(&tt, 0);
            if (tt.tv_sec < seq_expiry_tbl[pt_pkt->id_no]) {
                log();
                return ; 
            }

            /*
             *limit only one Internet destination
             */
            
            init_state = kProto_data;
            cur = create_and_insert_proxy_desc(pt_pkt->id_no, pkt->identifier, 0
                    addr, pt_pkt->dst_ip, ntohl(pt_pkt->dst_port), init_state,
                    kProxy_flag);
        }

        if (cur && pt_pkt->state == kProto_close) {
            log();
            cur->should_remove = 1;
            return ;
        }

        if (cur && cur->sock) {
            if (pt_pkt->state == kProto_data 
                    || pt_pkt->state == kProxy_start
                    || pt_pkt->state == kProto_ack) {
                handle_data((uint16_t)pt_pkt->ack, cur->send_ring, &cur->send_wait_ack, 
                        0, cur->send_idx, &cur->send_first_ack, &cur->remote_ack_val, is_pcap);
            } 
            handle_ack((uint16_t)pt_pkt->ack, cur->send_ring, 
                    &cur->send_wait_ack, 0,
                    cur->send_idx, &cur->send_first_ack, &cur->remote_ack_val, is_pcap);
            cur->last_activity = time_as_double();
        }

    }

}

forward_desc_t* create_fwd_desc(uint16_t seq_no, uint32_t data_len, char *data)
{
    forward_desc_t *fwd_desc = malloc(sizeof(forward_desc_t)+data_len);
    fwd_desc->seq_no = seq_no;
    fwd_desc->length = data_len;
    fwd_desc->remaining = data_len;

 </stddef>   if (data_len > 0) {memcpy(fwd_desc->data, data, data_len);}//TODO , more performance

    return fwd_desc;
}

void handle_ack(uint16_t seq_no, icmp_desc_t ring[], int *packets_awaiting_ack,
        int one_ack_only, int insert_idx, int *first_ack,
        uint16_t *remote_ack, int is_pcap)
{
//    ping_tunnel_pkt_t *pt_pkt;

    
    if (*packets_awaiting_ack > 0) {
        /*
        if (one_ack_only) {
            for (int i = 0; i < kPing_window_size; i++) {
                if (ring[i].ptk && ring[i].seq_no == seq_no && !is_pcap) {
                    pt_pkt = (ping_tunnel_pkt_t *)ring[i].pkt->data;
                    *remote_ack = (uint16_t)ntohl(pt_pkt->ack);
                    free(ring[i].pkt);
                    ring[i].pkt = 0;
                    (*packet_awaiting_ack)--;
                    if (*first_ack == i) {
                    }
                }
            }
        }
        */
        if (!one_ack_only) {
            int ring_i = ring_indexed_by_seq_no(ring, seq_no);

            if (ring_i) {
                free(ring[ring_i]->pkt);
                ring[ring_i]->pkt = NULL;
                (*packets_awaiting_ack)--;
                    //send_first_ack
                    //*first_ack 
                *first_ack = i+1;
            }
        } 


    }
}


