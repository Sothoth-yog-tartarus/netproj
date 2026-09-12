#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "global.h"
#include <pthread.h>
#include <sys/select.h>
#include <arpa/inet.h>

// 单位是byte
#define SIZE32 4
#define SIZE16 2
#define SIZE8  1

// 一些Flag
#define NO_FLAG 0
#define NO_WAIT 1
#define TIMEOUT 2
#define TRUE 1
#define FALSE 0

// 定义最大包长 防止IP层分片
#define MAX_DLEN 1375 	// 最大包内数据长度
#define MAX_LEN 1400 	// 最大包长度

/*
 * 注意: 说明书7.1/7.2条规定 SMSS = 1400-20 = 1380字节,
 * 但框架给出的MAX_DLEN是1375。这里两者不一致(相差5字节)。
 * 由于MAX_DLEN属于"限制修改内容"第3条(最大包长等全局定义),
 * 未经批准不能直接把它改成1380。
 * 本实现按"实际可用数据长度不超过MAX_DLEN"来处理,
 * 即实际使用的SMSS = MAX_DLEN = 1375。
 * 建议就这5字节的差异询问助教:是否要求严格用1380
 * (即需要申请修改MAX_DLEN),还是MAX_DLEN=1375就是当前平台的实际SMSS。
 */
#define SMSS MAX_DLEN

// TCP socket 状态定义
#define CLOSED 0
#define LISTEN 1
#define SYN_SENT 2
#define SYN_RECV 3
#define ESTABLISHED 4
#define FIN_WAIT_1 5
#define FIN_WAIT_2 6
#define CLOSE_WAIT 7
#define CLOSING 8
#define LAST_ACK 9
#define TIME_WAIT 10

// TCP 拥塞控制状态
#define SLOW_START 0
#define CONGESTION_AVOIDANCE 1
#define FAST_RECOVERY 2

// TCP 接受窗口大小
#define TCP_RECVWN_SIZE 32*MAX_DLEN // 比如最多放32个满载数据包

/*
 * 说明书7.3条要求: 发送/接收缓冲区容量不得小于5000*SMSS字节。
 * TCP_RECVWN_SIZE(32*MAX_DLEN,约44000字节)远小于这个要求,
 * 这个常量同样属于"限制修改内容",这里先不动它,
 * 而是让sending_buf/received_buf按需动态malloc/realloc增长,
 * 不受TCP_RECVWN_SIZE限制(该宏仅用作receiver_window_t里
 * 固定数组received的大小,以及一些窗口相关的经验值)。
 * 建议向助教确认: TCP_RECVWN_SIZE是否也需要按5000*SMSS调整,
 * 还是接收缓冲区允许用动态分配、不必用这个固定数组。
 */

// 序列号回绕安全比较: a是否严格早于b (在时序上)
static inline int seq_lt(uint32_t a, uint32_t b){
    return (int32_t)(a - b) < 0;
}
static inline int seq_leq(uint32_t a, uint32_t b){
    return (int32_t)(a - b) <= 0;
}

/* 在途未确认报文节点(发送窗口的重传队列) */
typedef struct pending_pkt {
    uint32_t seq;
    char* data;          // 该段数据的独立拷贝
    int len;
    struct timeval send_time;
    int retransmit_cnt;  // >0表示被重传过,Karn算法据此排除RTT采样
    struct pending_pkt* next;
} pending_pkt_t;

/* 接收方乱序缓存节点 */
typedef struct recv_block {
    uint32_t seq;
    int len;
    char* data;
    struct recv_block* next;
} recv_block_t;

// TCP 发送窗口
typedef struct {
	uint16_t window_size;

   uint32_t base;       // = snd_una
   uint32_t nextseq;    // = snd_nxt
   uint16_t rwnd;       // 对端通告的接收窗口(字节)
   uint16_t cwnd;       // 拥塞窗口(字节)
   uint16_t ssthresh;   // 慢启动阈值(字节)

   pending_pkt_t* inflight_head; // 按seq升序
   pending_pkt_t* inflight_tail;

   // RFC 6298 RTT/RTO
   double srtt;
   double rttvar;
   double rto;              // 单位: 秒
   int has_first_sample;

   // 重传定时器
   int timer_active;
   struct timeval timer_deadline;

   // 三次重复ACK快速重传
   uint32_t last_ack_recv;
   int dup_ack_cnt;
   int have_last_ack;

   // 零窗口探测
   int zero_wnd_probing;
   struct timeval next_probe_time;
   double probe_interval;   // 单位: 秒

   int cong_state;          // SLOW_START/CONGESTION_AVOIDANCE/FAST_RECOVERY

   // 主动关闭时记录自己发出的FIN序列号,用于识别FIN是否被ACK
   int fin_sent;
   uint32_t fin_seq;
} sender_window_t;

// TCP 接受窗口
typedef struct {
	char received[TCP_RECVWN_SIZE];

   uint32_t expect_seq;      // = rcv_nxt, 累计确认点
   recv_block_t* ooo_head;   // 乱序缓存链表,按seq升序
   int buf_used;             // 已交付但应用层还未tju_recv取走的字节数(即tju_tcp_t.received_len)
   uint16_t last_advertised_wnd; // 上一次通告的窗口值,用于接收方SWS避免
} receiver_window_t;

// TCP 窗口 每个建立了连接的TCP都包括发送和接受两个窗口
typedef struct {
	sender_window_t* wnd_send;
  	receiver_window_t* wnd_recv;
} window_t;

typedef struct {
	uint32_t ip;
	uint16_t port;
} tju_sock_addr;


// TJU_TCP 结构体 保存TJU_TCP用到的各种数据
typedef struct {
	int state; // TCP的状态

	uint32_t iss;//本端初始序列号
    uint32_t snd_una;//已发送但未确认
    uint32_t snd_nxt;//下一个发送序列号

    uint32_t irs;//对端初始序列号
    uint32_t rcv_nxt;//下一个期待序号



	tju_sock_addr bind_addr; // 存放bind和listen时该socket绑定的IP和端口
	tju_sock_addr established_local_addr; // 存放建立连接后 本机的 IP和端口
	tju_sock_addr established_remote_addr; // 存放建立连接后 连接对方的 IP和端口

	pthread_mutex_t send_lock; // 发送数据锁
	char* sending_buf; // 发送数据缓存区 (约定: sending_buf[0]对应序列号 window.wnd_send->base)
	int sending_len; // 发送数据缓存长度 (从base开始,包含已发未确认+尚未发送的全部数据)

	pthread_mutex_t recv_lock; // 接收数据锁
	char* received_buf; // 接收数据缓存区 (已按序交付,等待应用层tju_recv取走)
	int received_len; // 接收数据缓存长度

	pthread_cond_t wait_cond; // 可以被用来唤醒recv函数调用时等待的线程

	window_t window; // 发送和接受窗口

	pthread_mutex_t window_lock; // 保护窗口/重传队列的并发访问

	pthread_t retrans_thread;
	int retrans_thread_running;

	int close_requested;     // tju_close已被调用,发送逻辑据此在数据发完后才发FIN
	int peer_fin_received;   // 已收到对端FIN(用于tju_recv判断EOF, 避免永久阻塞)

	struct timeval time_wait_deadline; // TIME_WAIT状态的到期时间

} tju_tcp_t;

#endif
