#include "tju_tcp.h"

#include"math.h"


uint16_t get_available_window(tju_tcp_t* sock){

    int used=sock->received_len;

    int remain=TCP_RECVWN_SIZE-used;

    if(remain<0)
        remain=0;

    if(remain>65535)
        remain=65535;

    return (uint16_t)remain;
}//update3-cal rwnd

void check_ooo_packet(tju_tcp_t* sock){
    recv_block_t* cur=sock->window.wnd_recv->ooo_head;
    recv_block_t* prev=NULL;

    while(cur!=NULL){
        if(cur->seq==sock->rcv_nxt){

            pthread_mutex_lock(&(sock->recv_lock));

            if(sock->received_buf==NULL)
                sock->received_buf=malloc(cur->len);
            else
                sock->received_buf=realloc(
                    sock->received_buf,
                    sock->received_len+cur->len
                );

            memcpy(
                sock->received_buf+sock->received_len,
                cur->data,
                cur->len
            );

            sock->received_len+=cur->len;

            pthread_cond_signal(&(sock->wait_cond));

            pthread_mutex_unlock(&(sock->recv_lock));

            sock->rcv_nxt+=cur->len;

            if(prev==NULL)
                sock->window.wnd_recv->ooo_head=cur->next;
            else
                prev->next=cur->next;

            free(cur->data);
            free(cur);

            cur=sock->window.wnd_recv->ooo_head;
            prev=NULL;

        }
        else{
            prev=cur;
            cur=cur->next;
        }
    }
}//update4-1  save incurrent

void check_timeout(tju_tcp_t* sock){

    sender_window_t* sw=sock->window.wnd_send;

    if(sw==NULL)
        return;

    pending_pkt_t* cur=sw->inflight_head;

    if(cur==NULL)
        return;

    struct timeval now;

    gettimeofday(&now,NULL);

    long elapsed=
        (now.tv_sec-cur->send_time.tv_sec)*1000000+
        (now.tv_usec-cur->send_time.tv_usec);

    if(elapsed > sw->rto*1000000){

        char* pkt=create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            cur->seq,
            sock->rcv_nxt,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN+cur->len,
            ACK_FLAG_MASK,
            TCP_RECVWN_SIZE,
            0,
            cur->data,
            cur->len
        );

        sendToLayer3(
            pkt,
            DEFAULT_HEADER_LEN+cur->len
        );

        gettimeofday(
            &cur->send_time,
            NULL
        );

        cur->retransmit_cnt++;

        sw->rto*=2;

        if(sw->rto>60)
            sw->rto=60;//update4-3
    }
}//update4-2 重传检查

void* retransmission_thread(void* arg){

    tju_tcp_t* sock=(tju_tcp_t*)arg;

    while(sock->retrans_thread_running){

        check_timeout(sock);

        usleep(100000);
    }

    return NULL;
}

double timeval_diff(struct timeval *end,struct timeval *start){

    return (end->tv_sec-start->tv_sec)
        +(end->tv_usec-start->tv_usec)/1000000.0;
}//计算时间

void update_rto(sender_window_t* sw,double rtt){
    if(sw->has_first_sample==0){
        sw->srtt=rtt;
        sw->rttvar=rtt/2;
        sw->rto=sw->srtt+4*sw->rttvar;
        sw->has_first_sample=1;
    }
    else{
        sw->rttvar=
            0.75*sw->rttvar+
            0.25*fabs(sw->srtt-rtt);

        sw->srtt=
            0.875*sw->srtt+
            0.125*rtt;

        sw->rto=
            sw->srtt+
            4*sw->rttvar;
    }

    if(sw->rto<1)
        sw->rto=1;
}

/*
创建 TCP socket 
初始化对应的结构体    
设置初始状态为 CLOSED
*/
tju_tcp_t* tju_socket(){
    tju_tcp_t* sock = (tju_tcp_t*)malloc(sizeof(tju_tcp_t));
    memset(sock,0,sizeof(tju_tcp_t));//update2
    sock->state = CLOSED;
    //update1
    sock->iss = 0;
    sock->irs = 0;
    sock->snd_nxt = 0;
    sock->rcv_nxt = 0;
    
    pthread_mutex_init(&(sock->send_lock), NULL);
    sock->sending_buf = NULL;
    sock->sending_len = 0;

    pthread_mutex_init(&(sock->recv_lock), NULL);
    pthread_mutex_init(&(sock->window_lock), NULL);
    sock->received_buf = NULL;
    sock->received_len = 0;
    
    if(pthread_cond_init(&sock->wait_cond, NULL) != 0){
        perror("ERROR condition variable not set\n");
        exit(-1);
    }

    sock->window.wnd_send = NULL;
    sock->window.wnd_recv = NULL;
    sock->close_requested = 0;
    sock->peer_fin_received = 0;

    return sock;
}

/*
绑定监听的地址 包括ip和端口
*/
int tju_bind(tju_tcp_t* sock, tju_sock_addr bind_addr){
    sock->bind_addr = bind_addr;
    return 0;
}

/*
被动打开 监听bind的地址和端口
设置socket的状态为LISTEN
注册该socket到内核的监听socket哈希表
*/
int tju_listen(tju_tcp_t* sock){
    sock->state = LISTEN;
    int hashval = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
    listen_socks[hashval] = sock;
    return 0;
}

/*
接受连接 
返回与客户端通信用的socket
这里返回的socket一定是已经完成3次握手建立了连接的socket
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
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


/*
连接到服务端
该函数以一个socket为参数
调用函数前, 该socket还未建立连接
函数正常返回后, 该socket一定是已经完成了3次握手, 建立了连接
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
int tju_connect(tju_tcp_t* sock, tju_sock_addr target_addr){
        sock->established_remote_addr = target_addr;

    tju_sock_addr local_addr;
    local_addr.ip = inet_network("172.17.0.2");
    local_addr.port = 5678;
    sock->established_local_addr = local_addr;

    sock->iss = (uint32_t)rand();
    sock->snd_una = sock->iss;
    sock->snd_nxt = sock->iss + 1;
    sock->state = SYN_SENT;

    // 关键修正:先注册,再发包,避免 SYN|ACK 到达时找不到 socket
    int hashval = cal_hash(local_addr.ip, local_addr.port,
                            target_addr.ip, target_addr.port);
    established_socks[hashval] = sock;

    char* syn_pkt = create_packet_buf(
        local_addr.port, target_addr.port,
        sock->iss, 0,
        DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
        SYN_FLAG_MASK, TCP_RECVWN_SIZE, 0, NULL, 0
    );
    sendToLayer3(syn_pkt, DEFAULT_HEADER_LEN);

    while (sock->state != ESTABLISHED) {
        usleep(1000);
    }

    sock->window.wnd_send = malloc(sizeof(sender_window_t));
    memset(sock->window.wnd_send,0,sizeof(sender_window_t));

    sock->window.wnd_send->rto=1;//update4-3

    sock->window.wnd_recv = malloc(sizeof(receiver_window_t));
    memset(sock->window.wnd_recv,0,sizeof(receiver_window_t));

    sock->window.wnd_send->base = sock->snd_nxt;
    sock->window.wnd_send->nextseq = sock->snd_nxt;

    sock->window.wnd_recv->expect_seq = sock->rcv_nxt;//update2

    sock->window.wnd_recv->capacity = TCP_RECVWN_SIZE;
    sock->window.wnd_recv->used_size = 0;
    sock->window.wnd_recv->last_advertised_wnd = TCP_RECVWN_SIZE;//update3

    return 0;
}

int tju_send(tju_tcp_t* sock, const void *buffer, int len){
    pthread_mutex_lock(&(sock->send_lock));

    char* data=malloc(len);
    memcpy(data,buffer,len);

    uint32_t seq=sock->snd_nxt;

    char* msg=create_packet_buf(
        sock->established_local_addr.port,
        sock->established_remote_addr.port,
        seq,
        sock->rcv_nxt,
        DEFAULT_HEADER_LEN,
        DEFAULT_HEADER_LEN+len,
        ACK_FLAG_MASK,
        TCP_RECVWN_SIZE,
        0,
        data,
        len
    );

    sendToLayer3(msg,DEFAULT_HEADER_LEN+len);

    pending_pkt_t* pending=malloc(sizeof(pending_pkt_t));
    pending->seq=seq;
    pending->len=len;
    pending->data=malloc(len);
    pending->retransmitted=0;

    memcpy(
        pending->data,
        buffer,
        len
    );

    gettimeofday(
        &pending->send_time,
        NULL
    );

    pending->retransmit_cnt=0;
    pending->next=NULL;

    sender_window_t* sw=sock->window.wnd_send;

    if(sw->inflight_tail==NULL){
        sw->inflight_head=pending;
        sw->inflight_tail=pending;
    }
    else{
        sw->inflight_tail->next=pending;
        sw->inflight_tail=pending;
    }//update 4-2
    sock->snd_nxt+=len;

    free(data);

    pthread_mutex_unlock(&(sock->send_lock));

    return len;
}

int tju_recv(tju_tcp_t* sock, void *buffer, int len){
    pthread_mutex_lock(&(sock->recv_lock));

    while(sock->received_len<=0){

        pthread_cond_wait(
            &(sock->wait_cond),
            &(sock->recv_lock)
        );
    }

    int read_len;

    if(sock->received_len>=len)
        read_len=len;
    else
        read_len=sock->received_len;

    memcpy(
        buffer,
        sock->received_buf,
        read_len
    );

    if(read_len<sock->received_len){

        memmove(
            sock->received_buf,
            sock->received_buf+read_len,
            sock->received_len-read_len
        );

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
uint8_t flags=get_flags(pkt);

    if(sock->state==LISTEN && (flags&SYN_FLAG_MASK)){
        tju_tcp_t* new_conn=(tju_tcp_t*)malloc(sizeof(tju_tcp_t));
        memcpy(new_conn,sock,sizeof(tju_tcp_t));

        new_conn->state=SYN_RECV;

        new_conn->established_local_addr.ip=sock->bind_addr.ip;
        new_conn->established_local_addr.port=get_dst(pkt);

        new_conn->established_remote_addr.ip=inet_network("172.17.0.2");
        new_conn->established_remote_addr.port=get_src(pkt);

        new_conn->irs=get_seq(pkt);
        new_conn->rcv_nxt=new_conn->irs+1;

        new_conn->iss=(uint32_t)rand();
        new_conn->snd_una=new_conn->iss;
        new_conn->snd_nxt=new_conn->iss+1;

        char* synack=create_packet_buf(
            new_conn->established_local_addr.port,
            new_conn->established_remote_addr.port,
            new_conn->iss,
            new_conn->rcv_nxt,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN,
            SYN_FLAG_MASK|ACK_FLAG_MASK,
            TCP_RECVWN_SIZE,
            0,
            NULL,
            0
        );

        sendToLayer3(synack,DEFAULT_HEADER_LEN);

        int hashval=cal_hash(
            new_conn->established_local_addr.ip,
            new_conn->established_local_addr.port,
            new_conn->established_remote_addr.ip,
            new_conn->established_remote_addr.port
        );

        established_socks[hashval]=new_conn;

        return 0;
    }

    if(sock->state==SYN_SENT && (flags&SYN_FLAG_MASK) && (flags&ACK_FLAG_MASK)){
        if(get_ack(pkt)==sock->iss+1){
            sock->irs=get_seq(pkt);
            sock->rcv_nxt=sock->irs+1;

            char* ack=create_packet_buf(
                sock->established_local_addr.port,
                sock->established_remote_addr.port,
                sock->snd_nxt,
                sock->rcv_nxt,
                DEFAULT_HEADER_LEN,
                DEFAULT_HEADER_LEN,
                ACK_FLAG_MASK,
                TCP_RECVWN_SIZE,
                0,
                NULL,
                0
            );

            sendToLayer3(ack,DEFAULT_HEADER_LEN);
            sock->snd_una=sock->snd_nxt;
            sock->state=ESTABLISHED;

            sock->retrans_thread_running=1;

            pthread_create(
                &(sock->retrans_thread),
                NULL,
                retransmission_thread,
                sock
            );//update4-2

            int hashval=cal_hash(
                sock->established_local_addr.ip,
                sock->established_local_addr.port,
                sock->established_remote_addr.ip,
                sock->established_remote_addr.port
            );

            established_socks[hashval]=sock;
        }
        return 0;
    }

    if(sock->state==SYN_RECV && (flags&ACK_FLAG_MASK)){
        if(get_ack(pkt)==sock->snd_nxt){
            sock->state=ESTABLISHED;


            sock->window.wnd_send = malloc(sizeof(sender_window_t));
            memset(sock->window.wnd_send,0,sizeof(sender_window_t));

            sock->window.wnd_recv = malloc(sizeof(receiver_window_t));
            memset(sock->window.wnd_recv,0,sizeof(receiver_window_t));

            sock->window.wnd_send->base = sock->snd_nxt;
            sock->window.wnd_send->nextseq = sock->snd_nxt;

            sock->window.wnd_recv->expect_seq = sock->rcv_nxt;//update2

            sock->window.wnd_recv->capacity=TCP_RECVWN_SIZE;
            sock->window.wnd_recv->used_size=0;
            sock->window.wnd_recv->ooo_head=NULL;//update3-2

            sock->retrans_thread_running=1;
            pthread_create(
                &(sock->retrans_thread),
                NULL,
                retransmission_thread,
                sock
            );//update4-2
        }
        return 0;
    }

    if(sock->state==ESTABLISHED &&(flags&ACK_FLAG_MASK) &&get_plen(pkt)==DEFAULT_HEADER_LEN){

        uint32_t ack=get_ack(pkt);

        sender_window_t* sw=sock->window.wnd_send;

        if(sw!=NULL){

            if(ack==sw->last_ack_recv){

                sw->dup_ack_cnt++;

            }
            else{

                sw->last_ack_recv=ack;
                sw->dup_ack_cnt=0;

            }


            if(sw->dup_ack_cnt>=3){

                pending_pkt_t* lost=sw->inflight_head;

                if(lost!=NULL){

                    char* resend=create_packet_buf(
                        sock->established_local_addr.port,
                        sock->established_remote_addr.port,
                        lost->seq,
                        sock->rcv_nxt,
                        DEFAULT_HEADER_LEN,
                        DEFAULT_HEADER_LEN+lost->len,
                        ACK_FLAG_MASK,
                        TCP_RECVWN_SIZE,
                        0,
                        lost->data,
                        lost->len
                    );


                    sendToLayer3(
                        resend,
                        DEFAULT_HEADER_LEN+lost->len
                    );


                    gettimeofday(
                        &(lost->send_time),
                        NULL
                    );

                    lost->retransmit_cnt++;

                }

                sw->dup_ack_cnt=0;
            }
        }

        if(ack>sock->snd_una){


            sock->snd_una=ack;

            pending_pkt_t* cur=sock->window.wnd_send->inflight_head;
            pending_pkt_t* prev=NULL;

            while(cur!=NULL){

                if(cur->seq+cur->len<=ack){

                    if(cur->retransmitted==0){

                        struct timeval now;

                        gettimeofday(&now,NULL);

                        double rtt=
                            timeval_diff(
                                &now,
                                &cur->send_time
                            );

                        update_rto(
                            sock->window.wnd_send,
                            rtt
                        );
                    }


                    if(prev==NULL)
                        sock->window.wnd_send->inflight_head=cur->next;
                    else
                        prev->next=cur->next;

                    if(cur==sock->window.wnd_send->inflight_tail)
                        sock->window.wnd_send->inflight_tail=prev;

                    free(cur->data);

                    pending_pkt_t* tmp=cur;
                    cur=cur->next;

                    free(tmp);
                }
                else{
                    prev=cur;
                    cur=cur->next;
                }
            }//update 4-2
        }

        if(sock->window.wnd_send!=NULL){
            sock->window.wnd_send->rwnd=get_advertised_window(pkt);
        }

        return 0;
    }//update3

    if(sock->state==ESTABLISHED && !(flags&SYN_FLAG_MASK) && !(flags&FIN_FLAG_MASK)){
        uint32_t data_len=get_plen(pkt)-DEFAULT_HEADER_LEN;
        uint32_t seq=get_seq(pkt);//update3

        pthread_mutex_lock(&(sock->recv_lock));

        if(sock->received_buf==NULL)
            sock->received_buf=malloc(data_len);
        else
            sock->received_buf=realloc(sock->received_buf,sock->received_len+data_len);

        memcpy(
            sock->received_buf+sock->received_len,
            pkt+DEFAULT_HEADER_LEN,
            data_len
        );

        sock->received_len+=data_len;

        pthread_cond_signal(&(sock->wait_cond));

        pthread_mutex_unlock(&(sock->recv_lock));

        //sock->rcv_nxt+=data_len;
        if(seq==sock->rcv_nxt){
            sock->rcv_nxt+=data_len;
            check_ooo_packet(sock);
        }
        else if(seq < sock->rcv_nxt){
                recv_block_t* block=malloc(sizeof(recv_block_t));

                block->seq=seq;
                block->len=data_len;
                block->data=malloc(data_len);

                memcpy(
                    block->data,
                    pkt+DEFAULT_HEADER_LEN,
                    data_len
                );

                block->next=NULL;

                if(sock->window.wnd_recv->ooo_head==NULL){
                    sock->window.wnd_recv->ooo_head=block;
                }
                else{
                    recv_block_t* cur=sock->window.wnd_recv->ooo_head;

                    while(cur->next!=NULL)
                        cur=cur->next;

                    cur->next=block;
                }//update4-1
        }
        else{

        }
        //update4

        uint16_t wnd=get_available_window(sock);
        printf(
            "[流量控制] recv_buf=%d/%d rwnd=%d\n",
            sock->received_len,
            TCP_RECVWN_SIZE,
            wnd
        );//update4-4

        char* ack=create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            sock->snd_nxt,
            sock->rcv_nxt,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN,
            ACK_FLAG_MASK,
            //get_available_window(sock),//update3
            wnd,
            0,
            NULL,
            0
        );

        sendToLayer3(ack,DEFAULT_HEADER_LEN);

        return 0;
    }

    if(sock->state==ESTABLISHED && (flags&FIN_FLAG_MASK)){
        sock->rcv_nxt++;
        sock->state=CLOSE_WAIT;

        char* ack=create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            sock->snd_nxt,
            sock->rcv_nxt,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN,
            ACK_FLAG_MASK,
            TCP_RECVWN_SIZE,
            0,
            NULL,
            0
        );

        sendToLayer3(ack,DEFAULT_HEADER_LEN);

        return 0;
    }

    if(sock->state==FIN_WAIT_1 && (flags&ACK_FLAG_MASK)){
    sock->state=FIN_WAIT_2;
    return 0;
}

    if(sock->state==FIN_WAIT_2 && (flags&FIN_FLAG_MASK)){

        sock->rcv_nxt=get_seq(pkt)+1;

        char* ack=create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            sock->snd_nxt,
            sock->rcv_nxt,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN,
            ACK_FLAG_MASK,
            TCP_RECVWN_SIZE,
            0,
            NULL,
            0
        );

        sendToLayer3(ack,DEFAULT_HEADER_LEN);

        sock->state=TIME_WAIT;

        sleep(1);

        sock->state=CLOSED;

        return 0;
    }//update2

    return 0;
}

int tju_close (tju_tcp_t* sock){

    char* fin=create_packet_buf(
        sock->established_local_addr.port,
        sock->established_remote_addr.port,
        sock->snd_nxt,
        sock->rcv_nxt,
        DEFAULT_HEADER_LEN,
        DEFAULT_HEADER_LEN,
        FIN_FLAG_MASK|ACK_FLAG_MASK,
        TCP_RECVWN_SIZE,
        0,
        NULL,
        0
    );


    sendToLayer3(
        fin,
        DEFAULT_HEADER_LEN
    );

    sock->snd_nxt++;

    sock->state=FIN_WAIT_1;


    while(sock->state!=CLOSED){

        usleep(1000);

    }


    return 0;
}