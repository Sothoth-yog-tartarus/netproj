#include "tju_tcp.h"

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

    sock->window.wnd_recv = malloc(sizeof(receiver_window_t));
    memset(sock->window.wnd_recv,0,sizeof(receiver_window_t));

    sock->window.wnd_send->base = sock->snd_nxt;
    sock->window.wnd_send->nextseq = sock->snd_nxt;

    sock->window.wnd_recv->expect_seq = sock->rcv_nxt;//update2

    return 0;
}

int tju_send(tju_tcp_t* sock, const void *buffer, int len){
    pthread_mutex_lock(&(sock->send_lock));

    if(sock->sending_buf == NULL){
        sock->sending_buf = malloc(len);
    }
    else{
        sock->sending_buf = realloc(
            sock->sending_buf,
            sock->sending_len + len
        );
    }

    memcpy(
        sock->sending_buf + sock->sending_len,
        buffer,
        len
    );

    sock->sending_len += len;

    pthread_mutex_unlock(&(sock->send_lock));


    sender_window_t* sw = sock->window.wnd_send;

    while(sock->sending_len > 0){

        pthread_mutex_lock(&(sock->window_lock));

        uint32_t seq = sw->nextseq;

        int send_len = sock->sending_len;

        if(send_len > MAX_DLEN)
            send_len = MAX_DLEN;


        char* pkt = create_packet_buf(
            sock->established_local_addr.port,
            sock->established_remote_addr.port,
            seq,
            sock->rcv_nxt,
            DEFAULT_HEADER_LEN,
            DEFAULT_HEADER_LEN + send_len,
            ACK_FLAG_MASK,
            TCP_RECVWN_SIZE,
            0,
            sock->sending_buf,
            send_len
        );


        sendToLayer3(
            pkt,
            DEFAULT_HEADER_LEN + send_len
        );


        sw->nextseq += send_len;


        pthread_mutex_lock(&(sock->send_lock));

        memmove(
            sock->sending_buf,
            sock->sending_buf + send_len,
            sock->sending_len - send_len
        );

        sock->sending_len -= send_len;


        pthread_mutex_unlock(&(sock->send_lock));

        pthread_mutex_unlock(&(sock->window_lock));

    }


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
            //sock->state=ESTABLISHED;
            sock->state=ESTABLISHED;

            sock->window.wnd_send = malloc(sizeof(sender_window_t));
            memset(sock->window.wnd_send,0,sizeof(sender_window_t));

            sock->window.wnd_recv = malloc(sizeof(receiver_window_t));
            memset(sock->window.wnd_recv,0,sizeof(receiver_window_t));

            sock->window.wnd_send->base = sock->snd_nxt;
            sock->window.wnd_send->nextseq = sock->snd_nxt;

            sock->window.wnd_recv->expect_seq = sock->rcv_nxt;//update2
        }
        return 0;
    }

    if(sock->state==ESTABLISHED && flags==NO_FLAG){
        uint32_t data_len=get_plen(pkt)-DEFAULT_HEADER_LEN;

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

        sock->rcv_nxt+=data_len;

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