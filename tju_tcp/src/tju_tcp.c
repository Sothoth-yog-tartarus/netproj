#include "tju_tcp.h"
#include "math.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>

/* ================= 常量 ================= */
#define MSS 1360
#define MIN_RTO 1.0
#define MAX_RTO 60.0
#define CLOCK_GRANULARITY 0.001
#define MAX_RETRANSMIT 12

#define TCP_WINDOW_SIZE 65535
#define SEND_BUFFER_SIZE (8*1024*1024)
#define RECV_BUFFER_SIZE (20*1024*1024)

#define SYN_RETRY_INTERVAL 3
#define SYN_MAX_RETRY 20
#define FIN_RETRY_INTERVAL 3
#define FIN_MAX_RETRY 10

/* ============================================================
 * === WSCALE === 窗口缩放
 * ============================================================ */
static void make_wnd_ext(uint32_t avail, uint16_t* wnd_out, uint8_t* ext_out){
    uint32_t scale = 0;
    while(avail > 65535 && scale < 16){ avail >>= 1; scale++; }
    *wnd_out = (uint16_t)avail;
    *ext_out = (uint8_t)scale;
}
static uint32_t parse_peer_wnd(uint16_t wnd, uint8_t ext){
    if(ext > 16) ext = 16;
    return ((uint32_t)wnd) << ext;
}

typedef struct { sender_window_t* sw; uint32_t rwnd; } rwnd_ent_t;
static rwnd_ent_t g_rwnd_map[64];
static pthread_mutex_t g_rwnd_lock = PTHREAD_MUTEX_INITIALIZER;
static void set_rwnd(sender_window_t* sw, uint32_t w){
    if(!sw) return;
    pthread_mutex_lock(&g_rwnd_lock);
    int i, e = -1;
    for(i = 0; i < 64; i++){
        if(g_rwnd_map[i].sw == sw){ g_rwnd_map[i].rwnd = w; pthread_mutex_unlock(&g_rwnd_lock); return; }
        if(g_rwnd_map[i].sw == NULL && e < 0) e = i;
    }
    if(e >= 0){ g_rwnd_map[e].sw = sw; g_rwnd_map[e].rwnd = w; }
    pthread_mutex_unlock(&g_rwnd_lock);
}
static uint32_t get_rwnd(sender_window_t* sw){
    if(!sw) return 65535;
    uint32_t v = 65535;
    pthread_mutex_lock(&g_rwnd_lock);
    for(int i = 0; i < 64; i++) if(g_rwnd_map[i].sw == sw){ v = g_rwnd_map[i].rwnd; break; }
    pthread_mutex_unlock(&g_rwnd_lock);
    return v;
}

/* ============================================================
 * === RINGBUF === 接收环形读指针
 * ============================================================ */
typedef struct { tju_tcp_t* sock; uint32_t rpos; } readpos_ent_t;
static readpos_ent_t g_readpos[64];
static pthread_mutex_t g_readpos_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t readpos_get(tju_tcp_t* sock){
    uint32_t v = 0;
    pthread_mutex_lock(&g_readpos_lock);
    int i, e = -1;
    for(i = 0; i < 64; i++){
        if(g_readpos[i].sock == sock){ v = g_readpos[i].rpos; pthread_mutex_unlock(&g_readpos_lock); return v; }
        if(g_readpos[i].sock == NULL && e < 0) e = i;
    }
    if(e >= 0){ g_readpos[e].sock = sock; g_readpos[e].rpos = 0; }
    pthread_mutex_unlock(&g_readpos_lock);
    return 0;
}
static void readpos_set(tju_tcp_t* sock, uint32_t pos){
    pthread_mutex_lock(&g_readpos_lock);
    int i, e = -1;
    for(i = 0; i < 64; i++){
        if(g_readpos[i].sock == sock){ g_readpos[i].rpos = pos; pthread_mutex_unlock(&g_readpos_lock); return; }
        if(g_readpos[i].sock == NULL && e < 0) e = i;
    }
    if(e >= 0){ g_readpos[e].sock = sock; g_readpos[e].rpos = pos; }
    pthread_mutex_unlock(&g_readpos_lock);
}

static int ringbuf_append(tju_tcp_t* sock, const char* data, uint32_t len){
    if(sock->received_len + (int)len > RECV_BUFFER_SIZE) return -1;
    if(sock->received_buf == NULL){
        sock->received_buf = malloc(RECV_BUFFER_SIZE);
        sock->received_len = 0;
        readpos_set(sock, 0);
    }
    uint32_t rpos = readpos_get(sock);
    uint32_t wpos = (rpos + (uint32_t)sock->received_len) % RECV_BUFFER_SIZE;
    if(wpos + len <= RECV_BUFFER_SIZE){
        memcpy(sock->received_buf + wpos, data, len);
    } else {
        uint32_t first = RECV_BUFFER_SIZE - wpos;
        memcpy(sock->received_buf + wpos, data, first);
        memcpy(sock->received_buf, data + first, len - first);
    }
    sock->received_len += (int)len;
    return 0;
}

/* ============================================================
 * 全局发送队列
 * ============================================================ */
#define TXQ_CAP 16384
typedef struct { char* msg; int len; } tx_ent_t;
static tx_ent_t g_txq[TXQ_CAP];
static int g_tx_head = 0, g_tx_cnt = 0;
static pthread_mutex_t g_tx_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_tx_cond = PTHREAD_COND_INITIALIZER;
static int g_tx_started = 0;

static int tx_enqueue(char* msg, int plen){
    int ok = 0;
    pthread_mutex_lock(&g_tx_mutex);
    if(g_tx_cnt < TXQ_CAP){
        int idx = (g_tx_head + g_tx_cnt) % TXQ_CAP;
        g_txq[idx].msg = msg;
        g_txq[idx].len = plen;
        g_tx_cnt++;
        ok = 1;
    }
    pthread_mutex_unlock(&g_tx_mutex);
    if(ok) pthread_cond_signal(&g_tx_cond);
    else free(msg);
    return ok;
}

static void* tx_thread_fn(void* arg){
    (void)arg;
    while(1){
        char* msg; int len;
        pthread_mutex_lock(&g_tx_mutex);
        while(g_tx_cnt == 0)
            pthread_cond_wait(&g_tx_cond, &g_tx_mutex);
        msg = g_txq[g_tx_head].msg;
        len = g_txq[g_tx_head].len;
        g_tx_head = (g_tx_head + 1) % TXQ_CAP;
        g_tx_cnt--;
        pthread_mutex_unlock(&g_tx_mutex);
        sendToLayer3(msg, len);
        free(msg);
    }
    return NULL;
}

static void ensure_tx_thread(void){
    if(g_tx_started) return;
    pthread_mutex_lock(&g_tx_mutex);
    if(!g_tx_started){
        pthread_t tid;
        if(pthread_create(&tid, NULL, tx_thread_fn, NULL) == 0){
            pthread_detach(tid);
            g_tx_started = 1;
        }
    }
    pthread_mutex_unlock(&g_tx_mutex);
}

/* ============================================================
 * ZWP 状态
 * ============================================================ */
typedef struct zwp_state {
    tju_tcp_t* sock;
    uint64_t last_us;
    double interval_ms;
    struct zwp_state* next;
} zwp_state_t;

static zwp_state_t* g_zwp_head = NULL;
static pthread_mutex_t g_zwp_mutex = PTHREAD_MUTEX_INITIALIZER;

static zwp_state_t* get_zwp_state(tju_tcp_t* sock){
    pthread_mutex_lock(&g_zwp_mutex);
    zwp_state_t* cur = g_zwp_head;
    while(cur != NULL){
        if(cur->sock == sock){ pthread_mutex_unlock(&g_zwp_mutex); return cur; }
        cur = cur->next;
    }
    zwp_state_t* state = malloc(sizeof(zwp_state_t));
    state->sock = sock;
    state->last_us = 0;
    state->interval_ms = 1000.0;
    state->next = g_zwp_head;
    g_zwp_head = state;
    pthread_mutex_unlock(&g_zwp_mutex);
    return state;
}

/* ============================================================
 * 序号安全比较
 * ============================================================ */
static int seq_lt(uint32_t a, uint32_t b){ return (int32_t)(a-b) < 0; }
static int seq_gt(uint32_t a, uint32_t b){ return (int32_t)(a-b) > 0; }
static int seq_ge(uint32_t a, uint32_t b){ return (int32_t)(a-b) >= 0; }

/* ============================================================
 * 发送缓冲区（环形，不搬数据）
 * ============================================================ */
typedef struct send_buffer {
    char* data;
    uint32_t capacity;
    uint32_t base_seq;
    uint32_t next_seq;
    uint32_t app_end_seq;
} send_buffer_t;

static void init_send_buffer(tju_tcp_t* sock){
    if(sock->window.wnd_send == NULL){
        sock->window.wnd_send = malloc(sizeof(sender_window_t));
        memset(sock->window.wnd_send, 0, sizeof(sender_window_t));
        sock->window.wnd_send->rto = MIN_RTO;
        sock->window.wnd_send->rwnd = TCP_WINDOW_SIZE;
        sock->window.wnd_send->base = sock->snd_una;
        sock->window.wnd_send->nextseq = sock->snd_nxt;
        sock->window.wnd_send->dup_ack_cnt = 0;

        send_buffer_t* sbuf = malloc(sizeof(send_buffer_t));
        sbuf->data = malloc(SEND_BUFFER_SIZE);
        sbuf->capacity = SEND_BUFFER_SIZE;
        sbuf->base_seq = sock->snd_nxt;
        sbuf->next_seq = sock->snd_nxt;
        sbuf->app_end_seq = sock->snd_nxt;
        sock->sending_buf = (char*)sbuf;

        set_rwnd(sock->window.wnd_send, TCP_WINDOW_SIZE);
    }
}

static void init_window(tju_tcp_t* sock){
    init_send_buffer(sock);
    if(sock->window.wnd_recv == NULL){
        sock->window.wnd_recv = malloc(sizeof(receiver_window_t));
        memset(sock->window.wnd_recv, 0, sizeof(receiver_window_t));
        sock->window.wnd_recv->expect_seq = sock->rcv_nxt;
        sock->window.wnd_recv->capacity = RECV_BUFFER_SIZE;
        sock->window.wnd_recv->used_size = 0;
        sock->window.wnd_recv->ooo_head = NULL;
        sock->window.wnd_recv->last_advertised_wnd = TCP_WINDOW_SIZE;
    }
}

/* === FIX: 用 used_size 计数器代替遍历 ooo_head === */
static uint32_t get_available_window_full(tju_tcp_t* sock){
    int used = sock->received_len;
    if(sock->window.wnd_recv != NULL){
        used += (int)sock->window.wnd_recv->used_size;
    }
    int remain = RECV_BUFFER_SIZE - used;
    if(remain < 0) remain = 0;
    if(remain < MSS) return 0;
    return (uint32_t)remain;
}

uint16_t get_available_window(tju_tcp_t* sock){
    uint32_t a = get_available_window_full(sock);
    if(a > 65535) a = 65535;
    return (uint16_t)a;
}

void send_window_update(tju_tcp_t* sock){
    send_buffer_t* sbuf = (send_buffer_t*)sock->sending_buf;
    if(!sbuf) return;
    uint16_t wf; uint8_t ef;
    make_wnd_ext(get_available_window_full(sock), &wf, &ef);
    char* ack_pkt = create_packet_buf(
        sock->established_local_addr.port,
        sock->established_remote_addr.port,
        sbuf->next_seq, sock->rcv_nxt,
        DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
        ACK_FLAG_MASK, wf, ef, NULL, 0
    );
    tx_enqueue(ack_pkt, DEFAULT_HEADER_LEN);
}

/* === FIX: 只检查链表头部，O(1) === */
void check_ooo_packet(tju_tcp_t* sock){
    if(sock->window.wnd_recv == NULL) return;

    int merged = 0;
    while(sock->window.wnd_recv->ooo_head != NULL &&
          sock->window.wnd_recv->ooo_head->seq == sock->rcv_nxt){

        recv_block_t* cur = sock->window.wnd_recv->ooo_head;

        pthread_mutex_lock(&(sock->recv_lock));
        int r = ringbuf_append(sock, cur->data, cur->len);
        if(r == 0){
            pthread_cond_signal(&(sock->wait_cond));
            sock->rcv_nxt += cur->len;
            merged = 1;
            pthread_mutex_unlock(&(sock->recv_lock));

            sock->window.wnd_recv->ooo_head = cur->next;
            sock->window.wnd_recv->used_size -= cur->len;
            free(cur->data);
            free(cur);
        } else {
            pthread_mutex_unlock(&(sock->recv_lock));
            break;
        }
    }
    if(merged) send_window_update(sock);
}

static uint64_t now_us(void){
    struct timeval tv; gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

void check_timeout(tju_tcp_t* sock){
    sender_window_t* sw = sock->window.wnd_send;
    send_buffer_t* sbuf = (send_buffer_t*)sock->sending_buf;
    if(sw == NULL || sbuf == NULL) return;

    pthread_mutex_lock(&(sock->send_lock));

    /* 零窗口探测 */
    if(get_rwnd(sw) == 0 && seq_lt(sbuf->base_seq, sbuf->app_end_seq)){
        zwp_state_t* zwp = get_zwp_state(sock);
        uint64_t now = now_us();
        if(zwp->last_us == 0){
            zwp->last_us = now;
        } else {
            double elapsed_ms = (now - zwp->last_us) / 1000.0;
            if(elapsed_ms >= zwp->interval_ms){
                uint32_t probe_seq = sbuf->base_seq;
                char b = sbuf->data[probe_seq % sbuf->capacity];
                uint16_t wf; uint8_t ef;
                make_wnd_ext(get_available_window_full(sock), &wf, &ef);
                char* probe = create_packet_buf(
                    sock->established_local_addr.port,
                    sock->established_remote_addr.port,
                    probe_seq, sock->rcv_nxt,
                    DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN + 1,
                    ACK_FLAG_MASK, wf, ef, &b, 1
                );
                pthread_mutex_unlock(&(sock->send_lock));
                tx_enqueue(probe, DEFAULT_HEADER_LEN + 1);
                pthread_mutex_lock(&(sock->send_lock));
                zwp->last_us = now;
                zwp->interval_ms *= 2.0;
                if(zwp->interval_ms > 60000.0) zwp->interval_ms = 60000.0;
            }
        }
        pthread_mutex_unlock(&(sock->send_lock));
        return;
    } else {
        zwp_state_t* zwp = get_zwp_state(sock);
        zwp->last_us = 0;
        zwp->interval_ms = 1000.0;
    }

    /* 超时重传：用 seq % capacity 定位 */
    pending_pkt_t* cur = sw->inflight_head;
    int retransmitted_count = 0;
    while(cur != NULL && retransmitted_count < 20){
        if(cur->retransmit_cnt >= MAX_RETRANSMIT){
            sock->state = CLOSED;
            pthread_mutex_unlock(&(sock->send_lock));
            return;
        }
        struct timeval now_tv;
        gettimeofday(&now_tv, NULL);
        double elapsed = (now_tv.tv_sec - cur->send_time.tv_sec) +
                         (now_tv.tv_usec - cur->send_time.tv_usec) / 1000000.0;
        double pkt_rto = sw->rto * (1 << cur->retransmit_cnt);
        if(pkt_rto > MAX_RTO) pkt_rto = MAX_RTO;
        if(elapsed >= pkt_rto){
            if(seq_ge(cur->seq, sbuf->base_seq)){
                uint32_t wpos = cur->seq % sbuf->capacity;
                uint16_t wf; uint8_t ef;
                make_wnd_ext(get_available_window_full(sock), &wf, &ef);
                char* pkt = create_packet_buf(
                    sock->established_local_addr.port,
                    sock->established_remote_addr.port,
                    cur->seq, sock->rcv_nxt,
                    DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN + cur->len,
                    ACK_FLAG_MASK, wf, ef,
                    sbuf->data + wpos, cur->len
                );
                pthread_mutex_unlock(&(sock->send_lock));
                tx_enqueue(pkt, DEFAULT_HEADER_LEN + cur->len);
                pthread_mutex_lock(&(sock->send_lock));
                gettimeofday(&cur->send_time, NULL);
                cur->retransmit_cnt++;
                cur->retransmitted = 1;
                retransmitted_count++;
            }
        }
        cur = cur->next;
    }
    pthread_mutex_unlock(&(sock->send_lock));
}

void* retransmission_thread(void* arg){
    tju_tcp_t* sock = (tju_tcp_t*)arg;
    while(sock->retrans_thread_running){
        check_timeout(sock);
        usleep(3000);
    }
    return NULL;
}

double timeval_diff(struct timeval *end, struct timeval *start){
    return (end->tv_sec - start->tv_sec) +
           (end->tv_usec - start->tv_usec) / 1000000.0;
}

void update_rto(sender_window_t* sw, double rtt){
    double alpha = 0.125, beta = 0.25;
    if(sw->has_first_sample == 0){
        sw->srtt = rtt; sw->rttvar = rtt / 2.0; sw->has_first_sample = 1;
    } else {
        sw->rttvar = (1 - beta) * sw->rttvar + beta * fabs(sw->srtt - rtt);
        sw->srtt = (1 - alpha) * sw->srtt + alpha * rtt;
    }
    double k = 4.0;
    sw->rto = sw->srtt + (k * sw->rttvar > CLOCK_GRANULARITY ? k * sw->rttvar : CLOCK_GRANULARITY);
    if(sw->rto < MIN_RTO) sw->rto = MIN_RTO;
    if(sw->rto > MAX_RTO) sw->rto = MAX_RTO;
}

/* ============================================================
 * Socket 接口
 * ============================================================ */
tju_tcp_t* tju_socket(){
    tju_tcp_t* sock = (tju_tcp_t*)malloc(sizeof(tju_tcp_t));
    memset(sock, 0, sizeof(tju_tcp_t));
    sock->state = CLOSED;
    pthread_mutex_init(&(sock->send_lock), NULL);
    pthread_mutex_init(&(sock->recv_lock), NULL);
    pthread_mutex_init(&(sock->window_lock), NULL);
    if(pthread_cond_init(&sock->wait_cond, NULL) != 0){ perror("cond init"); exit(-1); }
    sock->window.wnd_send = NULL;
    sock->window.wnd_recv = NULL;
    sock->sending_buf = NULL;
    sock->close_requested = 0;
    sock->peer_fin_received = 0;
    sock->retrans_thread_running = 0;
    ensure_tx_thread();
    return sock;
}

int tju_bind(tju_tcp_t* sock, tju_sock_addr bind_addr){ sock->bind_addr = bind_addr; return 0; }

int tju_listen(tju_tcp_t* sock){
    sock->state = LISTEN;
    int hashval = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
    listen_socks[hashval] = sock;
    return 0;
}

tju_tcp_t* tju_accept(tju_tcp_t* listen_sock){
    tju_tcp_t* new_conn = NULL;
    while(new_conn == NULL){
        for(int i = 0; i < MAX_SOCK; i++){
            if(established_socks[i] != NULL){
                tju_tcp_t* temp = established_socks[i];
                if(temp->state == ESTABLISHED &&
                   temp->window.wnd_send != NULL &&
                   temp->window.wnd_recv != NULL &&
                   temp->bind_addr.ip == listen_sock->bind_addr.ip &&
                   temp->bind_addr.port == listen_sock->bind_addr.port){
                    new_conn = temp; break;
                }
            }
        }
        if(new_conn == NULL) usleep(1000);
    }
    return new_conn;
}

int tju_connect(tju_tcp_t* sock, tju_sock_addr target_addr){
    sock->established_remote_addr = target_addr;
    tju_sock_addr local_addr;
    local_addr.ip = inet_network("172.17.0.5");
    local_addr.port = 5678;
    sock->established_local_addr = local_addr;
    sock->iss = (uint32_t)rand();
    sock->snd_una = sock->iss;
    sock->snd_nxt = sock->iss + 1;
    sock->state = SYN_SENT;
    int hashval = cal_hash(local_addr.ip, local_addr.port, target_addr.ip, target_addr.port);
    established_socks[hashval] = sock;

    uint16_t wf; uint8_t ef;
    make_wnd_ext(TCP_WINDOW_SIZE, &wf, &ef);
    char* syn_pkt = create_packet_buf(
        local_addr.port, target_addr.port,
        sock->iss, 0,
        DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
        SYN_FLAG_MASK, wf, ef, NULL, 0
    );
    tx_enqueue(syn_pkt, DEFAULT_HEADER_LEN);

    int retry = 0;
    struct timeval last_syn_sent;
    gettimeofday(&last_syn_sent, NULL);
    while(sock->state != ESTABLISHED && sock->state != CLOSED){
        usleep(1000);
        if(sock->state == ESTABLISHED) break;
        struct timeval now_tv;
        gettimeofday(&now_tv, NULL);
        double elapsed = (now_tv.tv_sec - last_syn_sent.tv_sec) +
                         (now_tv.tv_usec - last_syn_sent.tv_usec) / 1000000.0;
        if(elapsed >= SYN_RETRY_INTERVAL){
            retry++;
            if(retry >= SYN_MAX_RETRY) return -1;
            uint16_t w2; uint8_t e2;
            make_wnd_ext(TCP_WINDOW_SIZE, &w2, &e2);
            char* syn = create_packet_buf(
                local_addr.port, target_addr.port,
                sock->iss, 0,
                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                SYN_FLAG_MASK, w2, e2, NULL, 0
            );
            tx_enqueue(syn, DEFAULT_HEADER_LEN);
            last_syn_sent = now_tv;
        }
    }
    if(sock->state != ESTABLISHED) return -1;
    init_window(sock);
    if(!sock->retrans_thread_running){
        sock->retrans_thread_running = 1;
        pthread_create(&(sock->retrans_thread), NULL, retransmission_thread, sock);
    }
    return 0;
}

/* === FIX: 发送缓冲区用 seq % capacity 定位，写入处理回绕 === */
int tju_send(tju_tcp_t* sock, const void *buffer, int len){
    send_buffer_t* sbuf = (send_buffer_t*)sock->sending_buf;
    sender_window_t* sw = sock->window.wnd_send;
    if(!sbuf || !sw) return -1;
    int total_sent = 0;

    while(total_sent < len){
        pthread_mutex_lock(&(sock->send_lock));
        if(sock->state != ESTABLISHED){
            pthread_mutex_unlock(&(sock->send_lock));
            return total_sent > 0 ? total_sent : -1;
        }
        uint32_t buffered = sbuf->app_end_seq - sbuf->base_seq;
        while(buffered >= sbuf->capacity - MSS){
            pthread_mutex_unlock(&(sock->send_lock));
            usleep(1000);
            pthread_mutex_lock(&(sock->send_lock));
            buffered = sbuf->app_end_seq - sbuf->base_seq;
        }
        int space = sbuf->capacity - buffered;
        int chunk = len - total_sent;
        if(chunk > space) chunk = space;
        if(chunk > MSS * 4) chunk = MSS * 4;

        /* 环形写入 */
        uint32_t wpos = sbuf->app_end_seq % sbuf->capacity;
        if(wpos + (uint32_t)chunk <= sbuf->capacity){
            memcpy(sbuf->data + wpos, (const char*)buffer + total_sent, chunk);
        } else {
            uint32_t first = sbuf->capacity - wpos;
            memcpy(sbuf->data + wpos, (const char*)buffer + total_sent, first);
            memcpy(sbuf->data, (const char*)buffer + total_sent + first, chunk - first);
        }
        sbuf->app_end_seq += chunk;
        total_sent += chunk;

        uint32_t inflight = sbuf->next_seq - sbuf->base_seq;
        uint32_t effective_window = get_rwnd(sw);

        while(seq_lt(sbuf->next_seq, sbuf->app_end_seq) &&
              (effective_window == 0 || inflight < effective_window)){
            uint32_t remaining_window = effective_window > inflight ? effective_window - inflight : 0;
            if(remaining_window < MSS && inflight > 0) break;
            int send_len = sbuf->app_end_seq - sbuf->next_seq;
            if(send_len > MSS) send_len = MSS;
            if(send_len > (int)remaining_window && effective_window > 0)
                send_len = remaining_window;
            if(send_len <= 0) break;

            uint32_t seq = sbuf->next_seq;
            uint32_t spos = seq % sbuf->capacity;
            uint16_t wf; uint8_t ef;
            make_wnd_ext(get_available_window_full(sock), &wf, &ef);

            /* 提取待发数据（处理回绕） */
            char tmp[MSS];
            if(spos + (uint32_t)send_len <= sbuf->capacity){
                memcpy(tmp, sbuf->data + spos, send_len);
            } else {
                uint32_t first = sbuf->capacity - spos;
                memcpy(tmp, sbuf->data + spos, first);
                memcpy(tmp + first, sbuf->data, send_len - first);
            }

            char* msg = create_packet_buf(
                sock->established_local_addr.port,
                sock->established_remote_addr.port,
                seq, sock->rcv_nxt,
                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN + send_len,
                ACK_FLAG_MASK, wf, ef, tmp, send_len
            );

            pending_pkt_t* pending = malloc(sizeof(pending_pkt_t));
            pending->seq = seq;
            pending->len = send_len;
            pending->data = NULL;
            gettimeofday(&pending->send_time, NULL);
            pending->retransmit_cnt = 0;
            pending->retransmitted = 0;
            pending->next = NULL;

            if(sw->inflight_tail == NULL){
                sw->inflight_head = pending;
                sw->inflight_tail = pending;
            } else {
                sw->inflight_tail->next = pending;
                sw->inflight_tail = pending;
            }
            sbuf->next_seq += send_len;
            sw->nextseq = sbuf->next_seq;
            pthread_mutex_unlock(&(sock->send_lock));
            tx_enqueue(msg, DEFAULT_HEADER_LEN + send_len);
            pthread_mutex_lock(&(sock->send_lock));
            inflight += send_len;
        }
        pthread_mutex_unlock(&(sock->send_lock));
    }
    return total_sent;
}

int tju_recv(tju_tcp_t* sock, void *buffer, int len){
    pthread_mutex_lock(&(sock->recv_lock));
    while(sock->received_len <= 0){
        if(sock->state == CLOSE_WAIT || sock->state == CLOSED ||
           sock->peer_fin_received){
            pthread_mutex_unlock(&(sock->recv_lock));
            return 0;
        }
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
    }
    int read_len = (sock->received_len >= len) ? len : sock->received_len;
    uint32_t rpos = readpos_get(sock);
    char* dst = (char*)buffer;
    if(rpos + (uint32_t)read_len <= RECV_BUFFER_SIZE){
        memcpy(dst, sock->received_buf + rpos, read_len);
    } else {
        uint32_t first = RECV_BUFFER_SIZE - rpos;
        memcpy(dst, sock->received_buf + rpos, first);
        memcpy(dst + first, sock->received_buf, read_len - first);
    }
    readpos_set(sock, (rpos + (uint32_t)read_len) % RECV_BUFFER_SIZE);
    sock->received_len -= read_len;
    pthread_mutex_unlock(&(sock->recv_lock));
    send_window_update(sock);
    return read_len;
}

int tju_handle_packet(tju_tcp_t* sock, char* pkt){
    uint8_t flags = get_flags(pkt);
    send_buffer_t* sbuf = (send_buffer_t*)sock->sending_buf;

    if(sock->state == LISTEN && (flags & SYN_FLAG_MASK)){
        tju_tcp_t* new_conn = tju_socket();
        new_conn->state = SYN_RECV;
        new_conn->bind_addr = sock->bind_addr;
        new_conn->established_local_addr.ip = sock->bind_addr.ip;
        new_conn->established_local_addr.port = get_dst(pkt);
        new_conn->established_remote_addr.ip = inet_network("172.17.0.5");
        new_conn->established_remote_addr.port = get_src(pkt);
        new_conn->irs = get_seq(pkt);
        new_conn->rcv_nxt = new_conn->irs + 1;
        new_conn->iss = (uint32_t)rand();
        new_conn->snd_una = new_conn->iss;
        new_conn->snd_nxt = new_conn->iss + 1;
        init_window(new_conn);

        uint16_t wf; uint8_t ef;
        make_wnd_ext(TCP_WINDOW_SIZE, &wf, &ef);
        char* synack = create_packet_buf(
            new_conn->established_local_addr.port,
            new_conn->established_remote_addr.port,
            new_conn->iss, new_conn->rcv_nxt,
            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
            SYN_FLAG_MASK | ACK_FLAG_MASK, wf, ef, NULL, 0
        );
        tx_enqueue(synack, DEFAULT_HEADER_LEN);

        int hashval = cal_hash(
            new_conn->established_local_addr.ip,
            new_conn->established_local_addr.port,
            new_conn->established_remote_addr.ip,
            new_conn->established_remote_addr.port
        );
        established_socks[hashval] = new_conn;
        if(!new_conn->retrans_thread_running){
            new_conn->retrans_thread_running = 1;
            pthread_create(&(new_conn->retrans_thread), NULL,
                          retransmission_thread, new_conn);
        }
        return 0;
    }

    if(sock->state == SYN_SENT && (flags & SYN_FLAG_MASK) && (flags & ACK_FLAG_MASK)){
        if(get_ack(pkt) == sock->iss + 1){
            sock->irs = get_seq(pkt);
            sock->rcv_nxt = sock->irs + 1;

            uint16_t wf; uint8_t ef;
            make_wnd_ext(TCP_WINDOW_SIZE, &wf, &ef);
            char* ack = create_packet_buf(
                sock->established_local_addr.port,
                sock->established_remote_addr.port,
                sock->snd_nxt, sock->rcv_nxt,
                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                ACK_FLAG_MASK, wf, ef, NULL, 0
            );
            tx_enqueue(ack, DEFAULT_HEADER_LEN);
            sock->snd_una = sock->snd_nxt;

            init_window(sock);
            if(sock->window.wnd_send != NULL){
                uint32_t pw = parse_peer_wnd(get_advertised_window(pkt), get_ext(pkt));
                set_rwnd(sock->window.wnd_send, pw);
                printf("[CONNECT] peer initial rwnd=%u (wnd=%u ext=%u)\n",
                       (unsigned)pw, get_advertised_window(pkt), get_ext(pkt));
            }
            sock->state = ESTABLISHED;
            if(!sock->retrans_thread_running){
                sock->retrans_thread_running = 1;
                pthread_create(&(sock->retrans_thread), NULL,
                              retransmission_thread, sock);
            }
        }
        return 0;
    }

    if(sock->state == SYN_RECV && (flags & ACK_FLAG_MASK)){
        if(get_ack(pkt) == sock->snd_nxt){
            init_window(sock);
            if(sock->window.wnd_send != NULL){
                uint32_t pw = parse_peer_wnd(get_advertised_window(pkt), get_ext(pkt));
                set_rwnd(sock->window.wnd_send, pw);
            }
            sock->state = ESTABLISHED;
        }
        return 0;
    }

    if(sock->state == ESTABLISHED && (flags & ACK_FLAG_MASK)){
        uint32_t ack = get_ack(pkt);
        uint32_t advertised_wnd = parse_peer_wnd(get_advertised_window(pkt), get_ext(pkt));
        sender_window_t* sw = sock->window.wnd_send;

        if(sw != NULL && sbuf != NULL){
            pthread_mutex_lock(&(sock->send_lock));

            uint32_t old_rwnd = get_rwnd(sw);
            set_rwnd(sw, advertised_wnd);
            if(old_rwnd == 0 && advertised_wnd > 0){
                zwp_state_t* zwp = get_zwp_state(sock);
                zwp->last_us = 0;
                zwp->interval_ms = 1000.0;
            }

            if(seq_gt(ack, sbuf->base_seq) && !seq_gt(ack, sbuf->next_seq)){
                int has_rtt_sample = 0;
                struct timeval sample_time;

                /* === FIX: 环形缓冲，base_seq 前进即可，不搬数据 === */
                sbuf->base_seq = ack;
                sock->snd_una = ack;

                pending_pkt_t* cur = sw->inflight_head;
                pending_pkt_t* prev = NULL;
                while(cur != NULL){
                    if(seq_ge(ack, cur->seq + cur->len)){
                        if(cur->retransmitted == 0 && !has_rtt_sample){
                            sample_time = cur->send_time;
                            has_rtt_sample = 1;
                        }
                        if(prev == NULL) sw->inflight_head = cur->next;
                        else prev->next = cur->next;
                        if(cur == sw->inflight_tail) sw->inflight_tail = prev;
                        pending_pkt_t* tmp = cur;
                        cur = cur->next;
                        free(tmp);
                    } else { prev = cur; cur = cur->next; }
                }
                if(has_rtt_sample){
                    struct timeval now_tv;
                    gettimeofday(&now_tv, NULL);
                    double rtt = timeval_diff(&now_tv, &sample_time);
                    update_rto(sw, rtt);
                }
                sw->base = ack;
                sw->last_ack_recv = ack;
                sw->dup_ack_cnt = 0;
            }
            else if(ack == sbuf->base_seq && sw->inflight_head != NULL){
                sw->dup_ack_cnt++;
                if(sw->dup_ack_cnt == 3){
                    pending_pkt_t* lost = sw->inflight_head;
                    while(lost != NULL && seq_ge(ack, lost->seq + lost->len)) lost = lost->next;
                    if(lost != NULL && seq_ge(lost->seq, sbuf->base_seq)){
                        uint32_t spos = lost->seq % sbuf->capacity;
                        uint16_t wf; uint8_t ef;
                        make_wnd_ext(get_available_window_full(sock), &wf, &ef);
                        char tmp2[MSS];
                        if(spos + (uint32_t)lost->len <= sbuf->capacity){
                            memcpy(tmp2, sbuf->data + spos, lost->len);
                        } else {
                            uint32_t first = sbuf->capacity - spos;
                            memcpy(tmp2, sbuf->data + spos, first);
                            memcpy(tmp2 + first, sbuf->data, lost->len - first);
                        }
                        char* resend = create_packet_buf(
                            sock->established_local_addr.port,
                            sock->established_remote_addr.port,
                            lost->seq, sock->rcv_nxt,
                            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN + lost->len,
                            ACK_FLAG_MASK, wf, ef, tmp2, lost->len
                        );
                        pthread_mutex_unlock(&(sock->send_lock));
                        tx_enqueue(resend, DEFAULT_HEADER_LEN + lost->len);
                        pthread_mutex_lock(&(sock->send_lock));
                        gettimeofday(&lost->send_time, NULL);
                        lost->retransmit_cnt++;
                        lost->retransmitted = 1;
                    }
                }
            }
            pthread_mutex_unlock(&(sock->send_lock));
        }

        if(get_plen(pkt) > DEFAULT_HEADER_LEN && !(flags & SYN_FLAG_MASK)){
            uint32_t data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
            uint32_t seq = get_seq(pkt);

            if(data_len > 0 && !(flags & FIN_FLAG_MASK)){
                uint32_t avail_full = get_available_window_full(sock);

                if(data_len > avail_full){
                    uint16_t wf; uint8_t ef;
                    make_wnd_ext(avail_full, &wf, &ef);
                    char* ack_pkt = create_packet_buf(
                        sock->established_local_addr.port,
                        sock->established_remote_addr.port,
                        sbuf ? sbuf->next_seq : sock->snd_nxt, sock->rcv_nxt,
                        DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                        ACK_FLAG_MASK, wf, ef, NULL, 0
                    );
                    tx_enqueue(ack_pkt, DEFAULT_HEADER_LEN);
                    return 0;
                }

                if(seq == sock->rcv_nxt){
                    pthread_mutex_lock(&(sock->recv_lock));
                    int r = ringbuf_append(sock, pkt + DEFAULT_HEADER_LEN, data_len);
                    if(r == 0){
                        pthread_cond_signal(&(sock->wait_cond));
                        sock->rcv_nxt += data_len;
                        pthread_mutex_unlock(&(sock->recv_lock));
                        check_ooo_packet(sock);
                    } else {
                        pthread_mutex_unlock(&(sock->recv_lock));
                        return 0;
                    }
                }
                else if(seq_gt(seq, sock->rcv_nxt) &&
                        seq < sock->rcv_nxt + RECV_BUFFER_SIZE){
                    if(sock->window.wnd_recv != NULL){
                        /* === FIX: 用 used_size 判断容量，不再遍历 === */
                        if(sock->window.wnd_recv->used_size + data_len < RECV_BUFFER_SIZE / 2){
                            recv_block_t* block = malloc(sizeof(recv_block_t));
                            block->seq = seq;
                            block->len = data_len;
                            block->data = malloc(data_len);
                            memcpy(block->data, pkt + DEFAULT_HEADER_LEN, data_len);
                            block->next = NULL;

                            int inserted = 0;
                            if(sock->window.wnd_recv->ooo_head == NULL){
                                sock->window.wnd_recv->ooo_head = block;
                                inserted = 1;
                            } else {
                                recv_block_t* cur = sock->window.wnd_recv->ooo_head;
                                recv_block_t* prev_blk = NULL;
                                while(cur != NULL && seq_lt(cur->seq, seq)){ prev_blk = cur; cur = cur->next; }
                                if(cur != NULL && cur->seq == seq){
                                    free(block->data); free(block);
                                } else if(prev_blk == NULL){
                                    block->next = sock->window.wnd_recv->ooo_head;
                                    sock->window.wnd_recv->ooo_head = block;
                                    inserted = 1;
                                } else {
                                    block->next = prev_blk->next;
                                    prev_blk->next = block;
                                    inserted = 1;
                                }
                            }
                            if(inserted){
                                sock->window.wnd_recv->used_size += data_len;
                            }
                        }
                    }
                }

                uint16_t wf; uint8_t ef;
                make_wnd_ext(get_available_window_full(sock), &wf, &ef);
                char* ack_pkt = create_packet_buf(
                    sock->established_local_addr.port,
                    sock->established_remote_addr.port,
                    sbuf ? sbuf->next_seq : sock->snd_nxt, sock->rcv_nxt,
                    DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                    ACK_FLAG_MASK, wf, ef, NULL, 0
                );
                tx_enqueue(ack_pkt, DEFAULT_HEADER_LEN);
            }
        }

        if(flags & FIN_FLAG_MASK){
            sock->rcv_nxt++;
            sock->peer_fin_received = 1;
            sock->state = CLOSE_WAIT;
            uint16_t wf; uint8_t ef;
            make_wnd_ext(TCP_WINDOW_SIZE, &wf, &ef);
            char* ack = create_packet_buf(
                sock->established_local_addr.port,
                sock->established_remote_addr.port,
                sbuf ? sbuf->next_seq : sock->snd_nxt, sock->rcv_nxt,
                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                ACK_FLAG_MASK, wf, ef, NULL, 0
            );
            tx_enqueue(ack, DEFAULT_HEADER_LEN);
            pthread_cond_signal(&(sock->wait_cond));
        }
        return 0;
    }

    if(sock->state == FIN_WAIT_1 && (flags & ACK_FLAG_MASK)){ sock->state = FIN_WAIT_2; return 0; }

    if(sock->state == FIN_WAIT_2 && (flags & FIN_FLAG_MASK)){
        sock->rcv_nxt = get_seq(pkt) + 1;
        uint16_t wf; uint8_t ef;
        make_wnd_ext(TCP_WINDOW_SIZE, &wf, &ef);
        char* ack = create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            sbuf ? sbuf->next_seq : sock->snd_nxt, sock->rcv_nxt,
            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
            ACK_FLAG_MASK, wf, ef, NULL, 0
        );
        tx_enqueue(ack, DEFAULT_HEADER_LEN);
        sock->state = TIME_WAIT;
        usleep(100000);
        sock->state = CLOSED;
        pthread_cond_signal(&(sock->wait_cond));
        return 0;
    }

    if(sock->state == LAST_ACK && (flags & ACK_FLAG_MASK)){
        uint32_t ack = get_ack(pkt);
        if(sbuf && seq_ge(ack, sbuf->next_seq)){
            sock->state = CLOSED;
            pthread_cond_signal(&(sock->wait_cond));
        }
        return 0;
    }
    return 0;
}

int tju_close(tju_tcp_t* sock){
    send_buffer_t* sbuf = (send_buffer_t*)sock->sending_buf;
    if(sbuf && sock->window.wnd_send != NULL){
        int timeout = 0;
        while(seq_lt(sbuf->base_seq, sbuf->app_end_seq) && timeout < 60000){
            usleep(1000);
            timeout++;
        }
    }

    int need_fin = 0;
    if(sock->state == ESTABLISHED){ need_fin = 1; sock->state = FIN_WAIT_1; }
    else if(sock->state == CLOSE_WAIT){ need_fin = 1; sock->state = LAST_ACK; }

    if(need_fin){
        uint32_t fin_seq = sbuf ? sbuf->next_seq : sock->snd_nxt;
        if(sbuf) sbuf->next_seq++;
        else sock->snd_nxt++;

        uint16_t wf; uint8_t ef;
        make_wnd_ext(TCP_WINDOW_SIZE, &wf, &ef);
        char* fin = create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            fin_seq, sock->rcv_nxt,
            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
            FIN_FLAG_MASK | ACK_FLAG_MASK, wf, ef, NULL, 0
        );
        tx_enqueue(fin, DEFAULT_HEADER_LEN);

        struct timeval last_fin;
        gettimeofday(&last_fin, NULL);
        int retry = 0, total = 0;
        while(sock->state != CLOSED && sock->state != TIME_WAIT && total < 30000){
            usleep(1000); total++;
            if(sock->state != FIN_WAIT_1 && sock->state != LAST_ACK) continue;
            struct timeval now_tv;
            gettimeofday(&now_tv, NULL);
            double elapsed = (now_tv.tv_sec - last_fin.tv_sec) +
                             (now_tv.tv_usec - last_fin.tv_usec) / 1000000.0;
            if(elapsed >= FIN_RETRY_INTERVAL && retry < FIN_MAX_RETRY){
                retry++;
                uint16_t w2; uint8_t e2;
                make_wnd_ext(TCP_WINDOW_SIZE, &w2, &e2);
                char* fin2 = create_packet_buf(
                    sock->established_local_addr.port,
                    sock->established_remote_addr.port,
                    fin_seq, sock->rcv_nxt,
                    DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                    FIN_FLAG_MASK | ACK_FLAG_MASK, w2, e2, NULL, 0
                );
                tx_enqueue(fin2, DEFAULT_HEADER_LEN);
                last_fin = now_tv;
            }
        }
    }

    if(sock->retrans_thread_running){
        sock->retrans_thread_running = 0;
        pthread_join(sock->retrans_thread, NULL);
    }
    if(sock->window.wnd_send != NULL){
        pending_pkt_t* cur = sock->window.wnd_send->inflight_head;
        while(cur != NULL){
            pending_pkt_t* tmp = cur;
            cur = cur->next;
            free(tmp);
        }
        free(sock->window.wnd_send);
        sock->window.wnd_send = NULL;
    }
    if(sock->window.wnd_recv != NULL){
        recv_block_t* cur = sock->window.wnd_recv->ooo_head;
        while(cur != NULL){
            recv_block_t* tmp = cur;
            cur = cur->next;
            free(tmp->data);
            free(tmp);
        }
        free(sock->window.wnd_recv);
        sock->window.wnd_recv = NULL;
    }
    if(sbuf){
        free(sbuf->data);
        free(sbuf);
        sock->sending_buf = NULL;
    }
    if(sock->received_buf != NULL){
        free(sock->received_buf);
        sock->received_buf = NULL;
    }
    return 0;
}