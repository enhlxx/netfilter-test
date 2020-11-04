#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <string.h>
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

void usage() {
    printf("syntax : netfilter-test <host>");
    printf("sample : netfilter-test test.gilgil.net");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
        }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d ", ret);

    fputc('\n', stdout);

    return id;
}

bool block_host(unsigned char *data, char *host) {
    struct ip *ip = (struct ip *)data;
    if(ip->ip_p != IPPROTO_TCP) {
        printf("Not TCP.\n");
        return false;
    }
    int ip_hdr_len = ip->ip_hl * 4;
    int tot_len = ntohs(ip->ip_len);

    struct tcphdr *tcp = (struct tcphdr *)(data + ip_hdr_len);
    if(ntohs(tcp->th_dport) != 80) {
        printf("Not HTTP.\n");
        return false;
    }
    int tcp_hdr_len = tcp->th_off * 4;
    char *http = (char *)(data + ip_hdr_len + tcp_hdr_len);
    int host_len = strlen(host);
    for (int i = 0; i < tot_len - ip_hdr_len - tcp_hdr_len - 6; i++) {
        if(strncmp("Host: ", http + i, 6) == 0) {
            if(strncmp(host, http + i + 6, host_len) == 0 &&
                    http[i + 6 + host_len] == '\r' && http[i + 7 + host_len] == '\n') {
                return true;
            }
            return false;
        }
    }
    return false;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *cbdata) {
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");

    unsigned char *data;
    char *host = (char *)cbdata;
    uint32_t verdict = NF_ACCEPT;

    if (nfq_get_payload(nfa, &data) >= 0) {
        if(block_host(data, host) == true) {
            verdict = NF_DROP;
            printf("Host blocked.\n\n");
        } else {
            verdict = NF_ACCEPT;
            printf("Host not blocked.\n\n");
        }
    }

    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    char *host;

    if (argc != 2) {
        usage();
        return -1;
    }

    host = argv[1];

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, host);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
          */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
