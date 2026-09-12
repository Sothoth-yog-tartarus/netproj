#include "tju_tcp.h"
#include <math.h>

#define TJU_MSL 2.0            // 单位:秒。TIME_WAIT = 2*TJU_MSL
#define MAX_RETRANSMIT 5       // SYN/FIN 及普通数据段的最大重传次数,超过则放弃
#define CLOSE_WAIT_TIMEOUT 30.0 // tju_close等待缓冲区清空的超时上限(秒),超时返回失败

/* ============================================================
   通用小工具
   ============================================================ */
static double tv_diff_sec(struct timeval* later, struct timeval* earlier){
    return (later->tv_sec - earlier->tv_sec) + (later->tv_usec - earlier->tv_usec) / 1e6;
}
static void tv_now(struct timeval* tv){
    gettimeofday(tv, NULL);
}
static void tv_add_sec(struct timeval* base, double sec, struct timeval* out){
    double total = base->tv_sec + base->tv_usec / 1e6 + sec;
    out->tv_sec = (long)total;
    out->tv_usec = (long)((total - out->tv_sec) * 1e6);
}
static int min_int(int a, int b){ return a < b ? a : b; }
static int max_int(int a, int b){ return a > b ? a : b; }

/* ============================================================
   checksum: 沿用此前方案(8位,复用ext字段偏移19)
   若课程要求严格16位TCP标准校验和,需要在tju_packet_t新增字段,
   属于需要事先报备的修改范围,请自行确认后再升级。
   ============================================================ */
static uint8_t compute_checksum_8(char* pkt_buf, int total_len){
    uint32_t sum = 0;
    for(int i = 0; i < total_len; i++){
        if(i == 19) continue;
        sum += (uint8_t)pkt_buf[i];
    }
    return (uint8_t)(~sum & 0xFF);
}
static void set_checksum(char* pkt_buf, int total_len){
    pkt_buf[19] = (char)compute_checksum_8(pkt_buf, total_len);
}
static int verify_checksum(char* pkt_buf, int total_len){
    uint8_t stored = (uint8_t)get_ext(pkt_buf);
    uint8_t computed = compute_checksum_8(pkt_buf, total_len);
    return stored == computed;
}
static void send_packet_with_checksum(uint16_t src, uint16_t dst, uint32_t seq, uint32_t ack,
    uint16_t hlen, uint16_t plen, uint8_t flags, uint16_t adv_window, char* data, int len){
    char* pkt = create_packet_buf(src, dst, seq, ack, hlen, plen, flags, adv_window, 0, data, len);
    set_checksum(pkt, plen);
    sendToLayer3(pkt, plen);
}

/* ============================================================
   窗口初始化
   ============================================================ */
static void init_windows(tju_tcp_t* sock, uint32_t snd_initial, uint32_t rcv_initial){
    sender_window_t* sw = malloc(sizeof(sender_window_t));
    memset(sw, 0, sizeof(sender_window_t));
    sw->window_size   = TCP_RECVWN_SIZE;
    sw->base          = snd_initial;
    sw->nextseq       = snd_initial;
    sw->rwnd          = 65535;
    sw->ssthresh      = 65535;
    sw->cwnd          = 3 * SMSS;
    sw->has_first_sample = 0;
    sw->rto           = 1.0;
    sw->timer_active  = 0;
    sw->have_last_ack = 0;
    sw->dup_ack_cnt   = 0;
    sw->zero_wnd_probing = 0;
    sw->probe_interval = 1.0;
    sw->cong_state    = SLOW_START;
    sw->fin_sent      = 0;

    receiver_window_t* rw = malloc(sizeof(receiver_window_t));
    memset(rw->received, 0, TCP_RECVWN_SIZE);
    rw->expect_seq = rcv_initial;
    rw->ooo_head = NULL;
    rw->buf_used = 0;
    rw->last_advertised_wnd = TCP_RECVWN_SIZE < 65535 ? TCP_RECVWN_SIZE : 65535;

    sock->window.wnd_send = sw;
    sock->window.wnd_recv = rw;

    pthread_mutex_init(&(sock->window_lock), NULL);

    sock->close_requested = 0;
    sock->peer_fin_received = 0;
}
/* ============================================================
   RFC 6298 RTT/RTO 更新 (调用时需已持有window_lock)
   ============================================================ */
static void update_rto_with_sample(sender_window_t* sw, double R){
    const double alpha = 1.0/8.0;
    const double beta  = 1.0/4.0;
    const double G = 0.1; // 时钟粒度占位值(秒),按平台实际时钟精度调整

    if(!sw->has_first_sample){
        sw->srtt = R;
        sw->rttvar = R / 2.0;
        sw->has_first_sample = 1;
    }else{
        double diff = fabs(sw->srtt - R);
        sw->rttvar = (1 - beta) * sw->rttvar + beta * diff;
        sw->srtt = (1 - alpha) * sw->srtt + alpha * R;
    }
    sw->rto = sw->srtt + max_int((int)(G*1000), (int)(4 * sw->rttvar * 1000)) / 1000.0;
    if(sw->rto < 1.0) sw->rto = 1.0; // RFC6298建议RTO下限,课程平台若另有规定请调整
}

/* ============================================================
   在途报文队列管理 (调用时需已持有window_lock)
   ============================================================ */
static void inflight_append(sender_window_t* sw, uint32_t seq, char* data, int len){
    pending_pkt_t* node = malloc(sizeof(pending_pkt_t));
    node->seq = seq;
    node->len = len;
    node->data = malloc(len);
    memcpy(node->data, data, len);
    node->retransmit_cnt = 0;
    tv_now(&node->send_time);
    node->next = NULL;
    if(sw->inflight_tail){
        sw->inflight_tail->next = node;
        sw->inflight_tail = node;
    }else{
        sw->inflight_head = sw->inflight_tail = node;
    }
}

/* 释放所有 seq+len <= new_base 的节点; 若有资格采样(未被重传过)则做RTT采样 */
static void inflight_ack_advance(sender_window_t* sw, uint32_t new_base){
    struct timeval now;
    tv_now(&now);
    int sampled = 0;
    while(sw->inflight_head && seq_leq(sw->inflight_head->seq + sw->inflight_head->len, new_base)){
        pending_pkt_t* node = sw->inflight_head;
        // Karn算法: 只用未被重传过的报文采样RTT, 每次ACK处理最多采一个样本即可
        if(!sampled && node->retransmit_cnt == 0){
            double R = tv_diff_sec(&now, &node->send_time);
            update_rto_with_sample(sw, R);
            sampled = 1;
        }
        sw->inflight_head = node->next;
        free(node->data);
        free(node);
    }
    if(!sw->inflight_head) sw->inflight_tail = NULL;
}

/* ============================================================
   拥塞控制(基础Reno): 每次收到推进了base的新ACK时调用
   ============================================================ */
static void congestion_on_new_ack(sender_window_t* sw, int acked_bytes){
    if(sw->cong_state == SLOW_START){
        sw->cwnd = (uint16_t)min_int(65535, sw->cwnd + SMSS);
        if(sw->cwnd >= sw->ssthresh){
            sw->cong_state = CONGESTION_AVOIDANCE;
        }
    }else if(sw->cong_state == CONGESTION_AVOIDANCE){
        // cwnd += SMSS*SMSS/cwnd (每个RTT大约增加一个SMSS)
        int incr = (SMSS * SMSS) / (sw->cwnd > 0 ? sw->cwnd : SMSS);
        if(incr < 1) incr = 1;
        sw->cwnd = (uint16_t)min_int(65535, sw->cwnd + incr);
    }else if(sw->cong_state == FAST_RECOVERY){
        // 新ACK结束快速恢复
        sw->cwnd = sw->ssthresh;
        sw->cong_state = CONGESTION_AVOIDANCE;
    }
    (void)acked_bytes;
}

static void congestion_on_triple_dup_ack(sender_window_t* sw, int inflight_bytes){
    sw->ssthresh = (uint16_t)max_int(inflight_bytes / 2, 2 * SMSS);
    sw->cwnd = (uint16_t)(sw->ssthresh + 3 * SMSS);
    sw->cong_state = FAST_RECOVERY;
}

static int inflight_bytes_total(sender_window_t* sw){
    return (int)(sw->nextseq - sw->base);
}

/* ============================================================
   处理收到的ACK (调用时需已持有window_lock, 且需持有send_lock来动sending_buf)
   ack_num: 对方确认号  adv_window: 对方通告窗口
   触发发送逻辑在函数外由调用者负责(process_ack返回后调用try_send_data)
   ============================================================ */
static void process_ack(tju_tcp_t* sock, uint32_t ack_num, uint16_t adv_window){
    sender_window_t* sw = sock->window.wnd_send;

    sw->rwnd = adv_window;

    if(seq_lt(sw->base, ack_num) && seq_leq(ack_num, sw->nextseq)){
        // 新ACK,推进了累计确认点
        uint32_t delta = ack_num - sw->base;

        inflight_ack_advance(sw, ack_num);

        pthread_mutex_lock(&(sock->send_lock));
        if((int)delta < sock->sending_len){
            memmove(sock->sending_buf, sock->sending_buf + delta, sock->sending_len - delta);
        }
        sock->sending_len -= delta;
        pthread_mutex_unlock(&(sock->send_lock));

        sw->base = ack_num;
        sw->dup_ack_cnt = 0;
        sw->have_last_ack = 1;
        sw->last_ack_recv = ack_num;

        congestion_on_new_ack(sw, (int)delta);

        if(sw->base == sw->nextseq){
            sw->timer_active = 0; // 全部确认,停止定时器
        }else{
            tv_now(&sw->timer_deadline);
            struct timeval now;
            tv_now(&now);
            tv_add_sec(&now, sw->rto, &sw->timer_deadline);
            sw->timer_active = 1;
        }

        // FIN是否被确认
        if(sw->fin_sent && seq_leq(sw->fin_seq + 1, ack_num)){
            if(sock->state == FIN_WAIT_1){
                sock->state = FIN_WAIT_2;
            }else if(sock->state == CLOSING){
                struct timeval now;
                tv_now(&now);
                tv_add_sec(&now, 2*TJU_MSL, &sock->time_wait_deadline);
                sock->state = TIME_WAIT;
            }else if(sock->state == LAST_ACK){
                sock->state = CLOSED;
            }
        }

    }else if(ack_num == sw->base){
        // 重复ACK
        if(!sw->have_last_ack || sw->last_ack_recv != ack_num){
            sw->have_last_ack = 1;
            sw->last_ack_recv = ack_num;
            sw->dup_ack_cnt = 1;
        }else{
            sw->dup_ack_cnt++;
        }

        if(sw->dup_ack_cnt == 3){
            // 三次重复ACK, 快速重传最早未确认报文
            congestion_on_triple_dup_ack(sw, inflight_bytes_total(sw));
            if(sw->inflight_head){
                send_packet_with_checksum(
                    sock->established_local_addr.port,
                    sock->established_remote_addr.port,
                    sw->inflight_head->seq,
                    sock->rcv_nxt,
                    DEFAULT_HEADER_LEN,
                    DEFAULT_HEADER_LEN + sw->inflight_head->len,
                    ACK_FLAG_MASK,
                    TCP_RECVWN_SIZE,
                    sw->inflight_head->data,
                    sw->inflight_head->len
                );
                sw->inflight_head->retransmit_cnt++; // Karn: 标记为已重传,不可再采样RTT
                tv_now(&sw->inflight_head->send_time);
            }
        }else if(sw->cong_state == FAST_RECOVERY && sw->dup_ack_cnt > 3){
            // 快速恢复期间, 每多一个重复ACK, cwnd膨胀一个SMSS
            sw->cwnd = (uint16_t)min_int(65535, sw->cwnd + SMSS);
        }
    }
    // ack_num < base 的旧ACK, 忽略
}
/* ============================================================
   发送方主发送逻辑: 按 min(rwnd, cwnd) 窗口,尽量把未发送数据发出去
   内部自行加window_lock和send_lock, 外部调用前不要重复加锁
   ============================================================ */
static void try_send_data(tju_tcp_t* sock){
    pthread_mutex_lock(&(sock->window_lock));
    sender_window_t* sw = sock->window.wnd_send;
    if(sw == NULL){ pthread_mutex_unlock(&(sock->window_lock)); return; }

    if(sw->rwnd == 0){
        // 对方通告窗口为0, 不发新数据, 交给零窗口探测机制处理
        pthread_mutex_unlock(&(sock->window_lock));
        return;
    }

    pthread_mutex_lock(&(sock->send_lock));

    for(;;){
        uint32_t inflight = sw->nextseq - sw->base;
        uint32_t usable_window = min_int(sw->rwnd, sw->cwnd);
        if(inflight >= usable_window) break;

        int sent_offset = (int)(sw->nextseq - sw->base);
        int unsent_len = sock->sending_len - sent_offset;
        if(unsent_len <= 0) break; // 没有更多待发送数据

        int room = (int)(usable_window - inflight);
        int seg_len = min_int(min_int(SMSS, unsent_len), room);
        if(seg_len <= 0) break;

        /*
         * 发送端SWS避免(基本版): 如果这次能发的seg_len明显小于一个满段(SMSS),
         * 且还不是"缓冲区里剩余的最后一块数据"(即后面很可能还有数据会通过
         * 后续tju_send追加进来,不必着急发这一小片),就先不发,等窗口/数据
         * 积累得更充分再发,避免持续发送小包。
         * 判定"是否是最后一块": seg_len == unsent_len 且已经等于 room上限,
         * 说明这就是当前能发的全部,直接发出去。
         */
        int is_last_chunk = (seg_len == unsent_len);
        if(seg_len < SMSS && !is_last_chunk && (uint32_t)room < usable_window){
            break; // 窗口目前只够发一小块,且后面大概率还有数据,先攒着
        }

        uint32_t seg_seq = sw->nextseq;
        char* seg_data = sock->sending_buf + sent_offset;

        send_packet_with_checksum(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            seg_seq,
            sock->rcv_nxt,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN + seg_len,
            ACK_FLAG_MASK,
            TCP_RECVWN_SIZE,
            seg_data,
            seg_len
        );

        inflight_append(sw, seg_seq, seg_data, seg_len);
        sw->nextseq += seg_len;

        if(!sw->timer_active){
            struct timeval now;
            tv_now(&now);
            tv_add_sec(&now, sw->rto, &sw->timer_deadline);
            sw->timer_active = 1;
        }
    }

    pthread_mutex_unlock(&(sock->send_lock));
    pthread_mutex_unlock(&(sock->window_lock));
}

/* ============================================================
   接收方: 计算通告窗口, 含基本SWS避免
   调用时需持有recv_lock (因为要读received_len)
   ============================================================ */
static uint16_t compute_adv_window(tju_tcp_t* sock){
    receiver_window_t* rw = sock->window.wnd_recv;
    int used = sock->received_len; // 已交付但应用层还没取走的数据占用的“空间”
    int free_space = TCP_RECVWN_SIZE - used;
    if(free_space < 0) free_space = 0;
    uint16_t new_wnd = (uint16_t)min_int(free_space, 65535);

    // 接收方SWS避免: 窗口增量太小时,先不上调通告值(除非要通告为0或者从0恢复)
    int min_incr = min_int(SMSS, TCP_RECVWN_SIZE / 4);
    if(new_wnd > rw->last_advertised_wnd
       && (new_wnd - rw->last_advertised_wnd) < min_incr
       && rw->last_advertised_wnd != 0){
        new_wnd = rw->last_advertised_wnd;
    }
    rw->last_advertised_wnd = new_wnd;
    return new_wnd;
}

/* ============================================================
   接收方: 处理一段收到的数据(可能按序/乱序/重复/重叠)
   调用时需持有window_lock; 内部会自行加/放recv_lock
   返回值: 无。处理完毕后, 调用者负责发送ACK。
   ============================================================ */
static void handle_data_segment(tju_tcp_t* sock, uint32_t seq, char* data, int len){
    receiver_window_t* rw = sock->window.wnd_recv;
    if(len <= 0) return;

    if(seq_lt(seq, rw->expect_seq)){
        // seq < expect_seq: 全部或部分重复
        uint32_t seq_end = seq + (uint32_t)len;
        if(seq_leq(seq_end, rw->expect_seq)){
            return; // 完全是旧数据, 整段丢弃
        }
        // 部分重叠: 只保留 expect_seq 之后的新内容
        uint32_t overlap = rw->expect_seq - seq;
        data += overlap;
        len -= (int)overlap;
        seq = rw->expect_seq;
        // 落入下面 seq == expect_seq 的分支继续处理
    }

    if(seq == rw->expect_seq){
        pthread_mutex_lock(&(sock->recv_lock));
        if(sock->received_buf == NULL)
            sock->received_buf = malloc(len);
        else
            sock->received_buf = realloc(sock->received_buf, sock->received_len + len);
        memcpy(sock->received_buf + sock->received_len, data, len);
        sock->received_len += len;
        pthread_mutex_unlock(&(sock->recv_lock));

        rw->expect_seq += len;

        // 检查乱序缓存里是否有能接着交付的数据块, 可能需要连续消费多个
        int progressed = 1;
        while(progressed){
            progressed = 0;
            recv_block_t** pp = &rw->ooo_head;
            while(*pp){
                recv_block_t* blk = *pp;
                if(seq_leq(blk->seq + (uint32_t)blk->len, rw->expect_seq)){
                    // 这块数据已经完全过时(和已交付数据重叠), 丢弃
                    *pp = blk->next;
                    free(blk->data);
                    free(blk);
                    continue;
                }
                if(blk->seq == rw->expect_seq){
                    pthread_mutex_lock(&(sock->recv_lock));
                    if(sock->received_buf == NULL)
                        sock->received_buf = malloc(blk->len);
                    else
                        sock->received_buf = realloc(sock->received_buf, sock->received_len + blk->len);
                    memcpy(sock->received_buf + sock->received_len, blk->data, blk->len);
                    sock->received_len += blk->len;
                    pthread_mutex_unlock(&(sock->recv_lock));

                    rw->expect_seq += blk->len;
                    *pp = blk->next;
                    free(blk->data);
                    free(blk);
                    progressed = 1;
                    continue;
                }
                pp = &blk->next;
            }
        }

        pthread_mutex_lock(&(sock->recv_lock));
        pthread_cond_signal(&(sock->wait_cond));
        pthread_mutex_unlock(&(sock->recv_lock));

    }else if(seq_lt(rw->expect_seq, seq)){
        // 乱序到达, 暂存(去重: 若已存在相同seq的块则跳过)
        recv_block_t* p = rw->ooo_head;
        while(p){
            if(p->seq == seq) return; // 已缓存过, 忽略
            p = p->next;
        }
        recv_block_t* node = malloc(sizeof(recv_block_t));
        node->seq = seq;
        node->len = len;
        node->data = malloc(len);
        memcpy(node->data, data, len);

        // 按seq升序插入
        recv_block_t** pp = &rw->ooo_head;
        while(*pp && seq_lt((*pp)->seq, seq)) pp = &(*pp)->next;
        node->next = *pp;
        *pp = node;
    }
}

/* ============================================================
   零窗口探测: 在重传线程里周期性检查
   调用时需已持有window_lock
   ============================================================ */
static void check_zero_window_probe(tju_tcp_t* sock){
    sender_window_t* sw = sock->window.wnd_send;
    struct timeval now;
    tv_now(&now);

    if(sw->rwnd == 0){
        if(!sw->zero_wnd_probing){
            sw->zero_wnd_probing = 1;
            sw->probe_interval = sw->rto; // 首次探测: 零窗口持续一个RTO后发出
            tv_add_sec(&now, sw->probe_interval, &sw->next_probe_time);
        }else if(tv_diff_sec(&now, &sw->next_probe_time) >= 0){
            // 发送1字节探测包(取snd_una开始的1字节, 若暂无数据则发0字节探测)
            pthread_mutex_lock(&(sock->send_lock));
            int has_byte = sock->sending_len > 0;
            char probe_byte = has_byte ? sock->sending_buf[0] : 0;
            pthread_mutex_unlock(&(sock->send_lock));

            send_packet_with_checksum(
                sock->established_local_addr.port,
                sock->established_remote_addr.port,
                sw->base,
                sock->rcv_nxt,
                DEFAULT_HEADER_LEN,
                DEFAULT_HEADER_LEN + (has_byte ? 1 : 0),
                ACK_FLAG_MASK,
                TCP_RECVWN_SIZE,
                has_byte ? &probe_byte : NULL,
                has_byte ? 1 : 0
            );

            sw->probe_interval *= 2; // 后续探测间隔指数增长
            tv_add_sec(&now, sw->probe_interval, &sw->next_probe_time);
        }
    }else{
        sw->zero_wnd_probing = 0;
    }
}
/* ============================================================
   超时重传检查(在后台线程里周期调用)
   ============================================================ */
static void check_timeout_retransmit(tju_tcp_t* sock){
    sender_window_t* sw = sock->window.wnd_send;
    if(!sw->timer_active || !sw->inflight_head) return;

    struct timeval now;
    tv_now(&now);
    if(tv_diff_sec(&now, &sw->timer_deadline) < 0) return;

    // 超时: 重传最早未确认报文, RTO加倍, 重启定时器
    pending_pkt_t* node = sw->inflight_head;
    node->retransmit_cnt++; // Karn算法标记

    if(node->retransmit_cnt > MAX_RETRANSMIT){
        // 超过最大重传次数, 这里简单处理为放弃该连接
        // (课程平台若有明确的失败返回规定, 请在此处对接, 比如置位错误状态)
        sw->timer_active = 0;
        return;
    }

    send_packet_with_checksum(
        sock->established_local_addr.port,
        sock->established_remote_addr.port,
        node->seq,
        sock->rcv_nxt,
        DEFAULT_HEADER_LEN,
        DEFAULT_HEADER_LEN + node->len,
        ACK_FLAG_MASK,
        TCP_RECVWN_SIZE,
        node->data,
        node->len
    );
    tv_now(&node->send_time);

    sw->rto *= 2; // 指数退避
    tv_add_sec(&now, sw->rto, &sw->timer_deadline);
}

static void* retrans_timer_loop(void* arg){
    tju_tcp_t* sock = (tju_tcp_t*)arg;
    while(sock->retrans_thread_running){
        usleep(1000); // 1ms轮询粒度
        pthread_mutex_lock(&(sock->window_lock));
        if(sock->window.wnd_send){
            check_timeout_retransmit(sock);
            check_zero_window_probe(sock);
        }
        pthread_mutex_unlock(&(sock->window_lock));

        // TIME_WAIT超时检测
        if(sock->state == TIME_WAIT){
            struct timeval now;
            tv_now(&now);
            if(tv_diff_sec(&now, &sock->time_wait_deadline) >= 0){
                sock->state = CLOSED;
            }
        }
    }
    return NULL;
}

static void start_retrans_thread(tju_tcp_t* sock){
    sock->retrans_thread_running = 1;
    pthread_create(&sock->retrans_thread, NULL, retrans_timer_loop, sock);
}

/* ============================================================
   规定接口实现
   ============================================================ */

tju_tcp_t* tju_socket(){
    tju_tcp_t* sock = (tju_tcp_t*)malloc(sizeof(tju_tcp_t));
    sock->state = CLOSED;
    sock->iss = 0;
    sock->irs = 0;
    sock->snd_nxt = 0;
    sock->rcv_nxt = 0;

    pthread_mutex_init(&(sock->send_lock), NULL);
    sock->sending_buf = NULL;
    sock->sending_len = 0;

    pthread_mutex_init(&(sock->recv_lock), NULL);
    sock->received_buf = NULL;
    sock->received_len = 0;

    if(pthread_cond_init(&sock->wait_cond, NULL) != 0){
        perror("ERROR condition variable not set\n");
        exit(-1);
    }

    sock->window.wnd_send = NULL;
    sock->window.wnd_recv = NULL;

    sock->retrans_thread_running = 0;
    sock->close_requested = 0;
    sock->peer_fin_received = 0;

    return sock;
}

int tju_bind(tju_tcp_t* sock, tju_sock_addr bind_addr){
    sock->bind_addr = bind_addr;
    return 0;
}

int tju_listen(tju_tcp_t* sock){
    sock->state = LISTEN;
    int hashval = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
    listen_socks[hashval] = sock;
    return 0;
}

tju_tcp_t* tju_accept(tju_tcp_t* listen_sock){
    tju_tcp_t* new_conn=NULL;
    while(new_conn==NULL){
        for(int i=0;i<MAX_SOCK;i++){
            if(established_socks[i]!=NULL){
                tju_tcp_t* temp=established_socks[i];
                if(temp->state==ESTABLISHED &&
                temp->bind_addr.ip==listen_sock->bind_addr.ip &&
                temp->bind_addr.port==listen_sock->bind_addr.port){
                    new_conn=temp;
                    break;
                }
            }
        }
        if(new_conn==NULL)
            usleep(1000);
    }
    return new_conn;
}

int tju_connect(tju_tcp_t* sock, tju_sock_addr target_addr){
    sock->established_remote_addr=target_addr;

    tju_sock_addr local_addr;
    local_addr.ip=inet_network("172.17.0.5");   // 按当前测试环境确认过的客户端IP,如换环境请调整
    local_addr.port=5678;
    sock->established_local_addr=local_addr;

    sock->iss=(uint32_t)rand();
    sock->snd_una=sock->iss;
    sock->snd_nxt=sock->iss+1;
    sock->state=SYN_SENT;

    int hashval=cal_hash(local_addr.ip,local_addr.port,target_addr.ip,target_addr.port);
    established_socks[hashval]=sock;

    send_packet_with_checksum(local_addr.port,target_addr.port,sock->iss,0,
        DEFAULT_HEADER_LEN,DEFAULT_HEADER_LEN,SYN_FLAG_MASK,TCP_RECVWN_SIZE,NULL,0);

    while(sock->state!=ESTABLISHED){
        usleep(1000);
    }

    init_windows(sock, sock->snd_nxt, sock->rcv_nxt);
    start_retrans_thread(sock);

    return 0;
}

int tju_send(tju_tcp_t* sock, const void *buffer, int len){
    pthread_mutex_lock(&(sock->send_lock));
    if(sock->sending_buf == NULL)
        sock->sending_buf = malloc(len);
    else
        sock->sending_buf = realloc(sock->sending_buf, sock->sending_len + len);
    memcpy(sock->sending_buf + sock->sending_len, buffer, len);
    sock->sending_len += len;
    pthread_mutex_unlock(&(sock->send_lock));

    try_send_data(sock);
    return len;
}

int tju_recv(tju_tcp_t* sock, void *buffer, int len){
    pthread_mutex_lock(&(sock->recv_lock));

    while(sock->received_len<=0 && !sock->peer_fin_received){
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
    }

    if(sock->received_len <= 0 && sock->peer_fin_received){
        // 对端已关闭且无更多数据, 返回0表示EOF
        pthread_mutex_unlock(&(sock->recv_lock));
        return 0;
    }

    int read_len;
    if(sock->received_len>=len)
        read_len=len;
    else
        read_len=sock->received_len;

    memcpy(buffer, sock->received_buf, read_len);

    if(read_len<sock->received_len){
        memmove(sock->received_buf, sock->received_buf+read_len, sock->received_len-read_len);
        sock->received_len-=read_len;
    }else{
        free(sock->received_buf);
        sock->received_buf=NULL;
        sock->received_len=0;
    }

    pthread_mutex_unlock(&(sock->recv_lock));
    return read_len;
}

int tju_handle_packet(tju_tcp_t* sock, char* pkt){
    uint16_t plen = get_plen(pkt);

    if(!verify_checksum(pkt, plen)){
        return 0; // 校验失败, 丢弃, 不进入任何状态处理
    }

    uint8_t flags = get_flags(pkt);

    /* -------- 三次握手部分(与之前一致) -------- */
    if(sock->state==LISTEN && (flags&SYN_FLAG_MASK)){
        tju_tcp_t* new_conn=(tju_tcp_t*)malloc(sizeof(tju_tcp_t));
        memcpy(new_conn,sock,sizeof(tju_tcp_t));
        new_conn->state=SYN_RECV;
        new_conn->established_local_addr.ip=sock->bind_addr.ip;
        new_conn->established_local_addr.port=get_dst(pkt);
        new_conn->established_remote_addr.ip=inet_network("172.17.0.5");
        new_conn->established_remote_addr.port=get_src(pkt);
        new_conn->irs=get_seq(pkt);
        new_conn->rcv_nxt=new_conn->irs+1;
        new_conn->iss=(uint32_t)rand();
        new_conn->snd_una=new_conn->iss;
        new_conn->snd_nxt=new_conn->iss+1;
        new_conn->window.wnd_send = NULL;
        new_conn->window.wnd_recv = NULL;
        new_conn->retrans_thread_running = 0;
        new_conn->close_requested = 0;
        new_conn->peer_fin_received = 0;
        pthread_mutex_init(&(new_conn->send_lock), NULL);
        pthread_mutex_init(&(new_conn->recv_lock), NULL);
        pthread_cond_init(&(new_conn->wait_cond), NULL);
        new_conn->sending_buf = NULL;
        new_conn->sending_len = 0;
        new_conn->received_buf = NULL;
        new_conn->received_len = 0;

        send_packet_with_checksum(
            new_conn->established_local_addr.port, new_conn->established_remote_addr.port,
            new_conn->iss, new_conn->rcv_nxt, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
            SYN_FLAG_MASK|ACK_FLAG_MASK, TCP_RECVWN_SIZE, NULL, 0);

        int hashval=cal_hash(new_conn->established_local_addr.ip, new_conn->established_local_addr.port,
            new_conn->established_remote_addr.ip, new_conn->established_remote_addr.port);
        established_socks[hashval]=new_conn;
        return 0;
    }

    if(sock->state==SYN_SENT && (flags&SYN_FLAG_MASK) && (flags&ACK_FLAG_MASK)){
        if(get_ack(pkt)==sock->iss+1){
            sock->irs=get_seq(pkt);
            sock->rcv_nxt=sock->irs+1;
            send_packet_with_checksum(
                sock->established_local_addr.port, sock->established_remote_addr.port,
                sock->snd_nxt, sock->rcv_nxt, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                ACK_FLAG_MASK, TCP_RECVWN_SIZE, NULL, 0);
            sock->snd_una=sock->snd_nxt;
            sock->state=ESTABLISHED;
            int hashval=cal_hash(sock->established_local_addr.ip, sock->established_local_addr.port,
                sock->established_remote_addr.ip, sock->established_remote_addr.port);
            established_socks[hashval]=sock;
        }
        return 0;
    }

    if(sock->state==SYN_RECV && (flags&ACK_FLAG_MASK)){
        if(get_ack(pkt)==sock->snd_nxt){
            sock->state=ESTABLISHED;
            init_windows(sock, sock->snd_nxt, sock->rcv_nxt);
            start_retrans_thread(sock);
        }
        return 0;
    }

    /* -------- 数据传输 + 关闭阶段 -------- */
    if(sock->window.wnd_send == NULL || sock->window.wnd_recv == NULL){
        return 0; // 窗口还没初始化(理论上不应发生), 保险起见忽略
    }

    uint32_t seq = get_seq(pkt);
    uint32_t ack_num = get_ack(pkt);
    uint16_t adv_window = get_advertised_window(pkt);
    int data_len = (int)plen - DEFAULT_HEADER_LEN;

    if(sock->state==ESTABLISHED || sock->state==FIN_WAIT_1 || sock->state==FIN_WAIT_2
       || sock->state==CLOSING || sock->state==CLOSE_WAIT || sock->state==LAST_ACK
       || sock->state==TIME_WAIT){

        if(flags & ACK_FLAG_MASK){
            pthread_mutex_lock(&(sock->window_lock));
            process_ack(sock, ack_num, adv_window);
            pthread_mutex_unlock(&(sock->window_lock));
        }

        if(data_len > 0 &&
           (sock->state==ESTABLISHED || sock->state==FIN_WAIT_1 || sock->state==FIN_WAIT_2)){
            pthread_mutex_lock(&(sock->window_lock));
            handle_data_segment(sock, seq, pkt+DEFAULT_HEADER_LEN, data_len);
            uint16_t my_adv = compute_adv_window(sock);
            uint32_t my_ack = sock->window.wnd_recv->expect_seq;
            pthread_mutex_unlock(&(sock->window_lock));

            sock->rcv_nxt = my_ack;

            send_packet_with_checksum(
                sock->established_local_addr.port, sock->established_remote_addr.port,
                sock->snd_nxt, my_ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                ACK_FLAG_MASK, my_adv, NULL, 0);
        }

        if(flags & FIN_FLAG_MASK){
            pthread_mutex_lock(&(sock->window_lock));
            uint32_t expect = sock->window.wnd_recv->expect_seq;
            uint32_t fin_seq = seq + (uint32_t)data_len;
            int fin_in_order = (fin_seq == expect);
            if(fin_in_order){
                sock->window.wnd_recv->expect_seq += 1; // FIN占用一个序列号
            }
            uint32_t my_ack = sock->window.wnd_recv->expect_seq;
            uint16_t my_adv = compute_adv_window(sock);
            pthread_mutex_unlock(&(sock->window_lock));

            if(fin_in_order){
                sock->rcv_nxt = my_ack;
                sock->peer_fin_received = 1;

                send_packet_with_checksum(
                    sock->established_local_addr.port, sock->established_remote_addr.port,
                    sock->snd_nxt, my_ack, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                    ACK_FLAG_MASK, my_adv, NULL, 0);

                pthread_mutex_lock(&(sock->recv_lock));
                pthread_cond_signal(&(sock->wait_cond)); // 唤醒可能阻塞的tju_recv, 让其返回EOF
                pthread_mutex_unlock(&(sock->recv_lock));

                if(sock->state==ESTABLISHED){
                    sock->state=CLOSE_WAIT;
                }else if(sock->state==FIN_WAIT_1){
                    sock->state=CLOSING; // 同时关闭
                }else if(sock->state==FIN_WAIT_2){
                    struct timeval now;
                    tv_now(&now);
                    tv_add_sec(&now, 2*TJU_MSL, &sock->time_wait_deadline);
                    sock->state=TIME_WAIT;
                }
            }
            /*
             * 若FIN到达时前面还有数据缺口(fin_in_order==0), 简化处理为
             * 暂不消费FIN, 等前面数据补齐、expect_seq推进到fin_seq时,
             * 由于对端通常会在超时后重传这个FIN, 后续重传到达时
             * fin_in_order会变为真, 从而被正确处理。
             */
        }
        return 0;
    }

    return 0;
}

int tju_close(tju_tcp_t* sock){
    sock->close_requested = 1;

    // 等待此前已提交的发送数据全部被确认(sending_len归零),超时则返回失败
    struct timeval start, now;
    tv_now(&start);
    while(1){
        pthread_mutex_lock(&(sock->send_lock));
        int remaining = sock->sending_len;
        pthread_mutex_unlock(&(sock->send_lock));
        if(remaining <= 0) break;

        tv_now(&now);
        if(tv_diff_sec(&now, &start) > CLOSE_WAIT_TIMEOUT){
            return -1; // 明确返回失败状态, 不默认丢弃缓冲数据
        }
        usleep(1000);
    }

    pthread_mutex_lock(&(sock->window_lock));
    sender_window_t* sw = sock->window.wnd_send;
    uint32_t fin_seq = sw->nextseq;
    sw->fin_sent = 1;
    sw->fin_seq = fin_seq;
    sw->nextseq += 1;
    pthread_mutex_unlock(&(sock->window_lock));

    send_packet_with_checksum(
        sock->established_local_addr.port, sock->established_remote_addr.port,
        fin_seq, sock->rcv_nxt, DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
        FIN_FLAG_MASK|ACK_FLAG_MASK, TCP_RECVWN_SIZE, NULL, 0);

    if(sock->state==ESTABLISHED){
        sock->state=FIN_WAIT_1;
    }else if(sock->state==CLOSE_WAIT){
        sock->state=LAST_ACK;
    }

    tv_now(&start);
    while(sock->state!=CLOSED){
        usleep(1000);
        tv_now(&now);
        if(tv_diff_sec(&now, &start) > CLOSE_WAIT_TIMEOUT + 2*TJU_MSL + 5){
            return -1; // 长时间未能完成关闭握手, 返回失败
        }
    }

    sock->retrans_thread_running = 0;
    if(sock->retrans_thread){
        pthread_join(sock->retrans_thread, NULL);
    }

    return 0;
}
