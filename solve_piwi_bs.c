#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include "craptev1.h"
#include "crypto1_bs.h"
#include "crypto1_bs_crack.h"
#include <inttypes.h>
#include <math.h>
#include <time.h>
#define __STDC_FORMAT_MACROS
#define llx PRIx64
#define lli PRIi64
#define llu PRIu64
#define lu PRIu32
#define VT100_cleareol "\r\33[2K"

uint32_t **space, uid, now_need_time = 0, spend_time = 0;
uint64_t last_states_tested = 0, now_v = 0;
uint8_t thread_count = 1;
FILE *fp;
bool iscomputing = false;

char *wday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
time_t timep;
struct tm *p;

void get_now_time()
{
    time(&timep);          /*获得time_t结构的时间，UTC时间*/
    p = localtime(&timep); /*转换为struct tm结构的当地时间*/
}

int get_bits()
{
    return sizeof(int *) * 8;
}

void log_write_time()
{
    get_now_time();
    fprintf(fp, "[%d/%d/%d %s %d:%d:%d]", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, wday[p->tm_wday], p->tm_hour, p->tm_min, p->tm_sec);
}

void log_write(char *logtext)
{
    log_write_time();
    fprintf(fp, logtext);
}

uint64_t split(uint8_t p){
    return (((p & 0x8) >>3 )| ((p & 0x4) >> 2) << 8 | ((p & 0x2) >> 1) << 16 | (p & 0x1) << 24 );
}

uint32_t uid;
uint64_t *readnonces(char* fname){
    int i;
    FILE *f = fopen(fname, "rb");
    if (f == NULL) {
        fprintf(stderr, "打开文件失败!\n");
        log_write("打开文件失败!\n");
        exit(EXIT_FAILURE);
    }
    uint64_t *nonces = malloc(sizeof (uint64_t) <<  24);
    if(fread(&uid, 1, 4, f)){
        uid = rev32(uid);
    }
    fseek(f, 6, SEEK_SET);
    i = 0;
    while(!feof(f)){
        uint32_t nt_enc1, nt_enc2;
        uint8_t par_enc;
        if(fread(&nt_enc1, 1, 4, f) && fread(&nt_enc2, 1, 4, f) && fread(&par_enc, 1, 1, f)){
            nonces[i  ] = split(~(par_enc >>   4)) << 32 | nt_enc1;
            nonces[i+1] = split(~(par_enc & 0xff)) << 32 | nt_enc2;
            i += 2;
        }
    }
    nonces[i] = -1;
    fclose(f);
    return nonces;
}

void* crack_states_thread(void* x){
    const size_t thread_id = (size_t)x;
    int j;
    for(j = thread_id; space[j * 5]; j += thread_count) {
        const uint64_t key = crack_states_bitsliced(space + j * 5);
        if(key != -1){
            printf("\n已找到 Key: %012" llx "\n", key);
            log_write_time();
            fprintf(fp, "目标 uid [%04x] 已找到 Key: %012" llx "\n", uid, key);
            break;
        } else if(keys_found){
            break;
        }
    }
    return NULL;
}

void notify_status_offline(int sig)
{
    now_v = total_states_tested - last_states_tested;
    now_need_time = (now_v == 0) ? 0 : (total_states - total_states_tested) / now_v;
    printf( "计算中... %6.02f%%  速度: %" llu " keys/s  预计需要时间: %" llu " s\n", (100.0 * total_states_tested / (total_states)), now_v, now_need_time);
    last_states_tested = total_states_tested;
    //alarm(1);
    fflush(stdout);
    //notify_status_offline(1);
    //signal(SIGALRM, notify_status_offline);
}

void *progross_output()
{
    while (iscomputing)
    {
        notify_status_offline(1);
        sleep(1);
        spend_time++;
    }
    now_v = total_states_tested / ((spend_time == 0) ? 1 : spend_time);
}

int main(int argc, char* argv[]){
	printf("BS Crypto-1 HardNested 暴力破解程序 (%d-bits)\nCompiled by NKXingXh\n请勿用于违法用途\n\n", get_bits());
    if(argc < 2){
        printf("用法: %s <nonces.bin> [线程数]\n", argv[0]);
        return -1;
    }
    
    fp = fopen("HardNested.log", "a+");
    if (!fp)
    {
        printf("打开日志文件失败! ");
        return -1;
    }
    
    printf("正在读取 Nonces...\n");
    uint64_t *nonces = readnonces(argv[1]);
    printf("Deriving search space...\n");
    space = craptev1_get_space(nonces, 95, uid);
    total_states = craptev1_sizeof_space(space);

/*
#ifndef __WIN32
	thread_count = sysconf(_SC_NPROCESSORS_CONF);
#else
    thread_count = 1;
#endif*/
	if (argc >= 3) thread_count = *argv[3] - '0';
    else thread_count = 4;

    // append some zeroes to the end of the space to make sure threads don't go off into the wild
    size_t j = 0;
    for(j = 0; space[j]; j+=5){
    }
    size_t fill = j + (5*thread_count);
    for(; j < fill; j++) {
        space[j] = 0;
    }
    pthread_t threads[thread_count];
    size_t i;

    printf("\n正在初始化 BS crypto-1\n目标 uid [%04x]\n", uid);
    log_write("正在初始化 BS crypto-1\n");
    log_write_time();
    fprintf(fp, "目标 uid [%04x]\n", uid);
    crypto1_bs_init();
    printf("Using %u-bit bitslices\n", MAX_BITSLICES);

    uint8_t rollback_byte = **space;
    printf("Bitslicing rollback byte: %02x...\n", rollback_byte);
    // convert to 32 bit little-endian
    crypto1_bs_bitslice_value32(rev32((rollback_byte)), bitsliced_rollback_byte, 8);

    printf("Bitslicing nonces...\n");
    for(size_t tests = 0; tests < NONCE_TESTS; tests++){
        // pre-xor the uid into the decrypted nonces, and also pre-xor the uid parity into the encrypted parity bits - otherwise an exta xor is required in the decryption routine
        uint32_t test_nonce = uid^rev32(nonces[tests]);
        uint32_t test_parity = (nonces[tests]>>32)^rev32(uid);
        test_parity = ((parity(test_parity >> 24 & 0xff) & 1) | (parity(test_parity>>16 & 0xff) & 1)<<1 | (parity(test_parity>>8 & 0xff) & 1)<<2 | (parity(test_parity &0xff) & 1) << 3);
        crypto1_bs_bitslice_value32(test_nonce, bitsliced_encrypted_nonces[tests], 32);
        // convert to 32 bit little-endian
        crypto1_bs_bitslice_value32(~(test_parity)<<24, bitsliced_encrypted_parity_bits[tests], 4);
    }

    total_states_tested = 0;
    keys_found = 0;

    printf("\n启动 %u 线程来计算 %" llu " (~2^%0.2f) 种可能性\n", thread_count, total_states, log(total_states) / log(2));
    log_write_time();
    fprintf(fp, "启动 %u 线程来计算 %" llu " (~2^%0.2f) 种可能性\n", thread_count, total_states, log(total_states) / log(2));
    //printf("PRESS ANY KEY TO START...\n");
    //getchar();
    //signal(SIGALRM, notify_status_offline);
    //alarm(1);

    //启动输出线程
    iscomputing = true;
    pthread_t progross_t;
    pthread_create(&progross_t, NULL, progross_output, NULL);

    //启动计算线程
    for (i = 0; i < thread_count; i++)
    {
        pthread_create(&threads[i], NULL, crack_states_thread, (void *)i);
    }

    //等待所有计算线程执行完毕
    for (i = 0; i < thread_count; i++)
    {
        pthread_join(threads[i], 0);
    }

    //alarm(0);
    iscomputing = false;
    pthread_join(progross_t, 0);

    printf("\n尝试了 %" llu " 种可能性, 耗时 %lu s, 平均速度 %llu keys/s", total_states_tested, spend_time, now_v);
    log_write_time();
    fprintf(fp, "尝试了 %" llu " 种可能性, 耗时 %lu s, 平均速度 %llu keys/s", total_states_tested, spend_time, now_v);

    if (!keys_found)
    {
        fprintf(stderr, "没有找到结果 :(\n请检查 uid 是否正确\n");
        log_write("没有找到结果 :(");
    }

    craptev1_destroy_space(space);

    if (fp)
    {
        fclose(fp);
    }

    return 0;
}


