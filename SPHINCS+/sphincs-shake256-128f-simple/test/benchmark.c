#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <sys/utsname.h>  // 系统内核信息
#include <sys/sysinfo.h>  // 内存信息
#include <string.h>       // 字符串处理
#include <stdint.h>       // uint64_t 类型

#include "../api.h"
#include "../fors.h"
#include "../wots.h"
#include "../params.h"
#include "../rng.h"

#define SPX_MLEN 32
#define NTESTS 10

#define TEST_ROUNDS 20

/*
 * 修改说明摘要：
 * - 平台是虚拟的 ARM（无法使用 x86 RDTSCP/rdtsc 指令），并且 CPU 频率在虚拟平台上固定为 1.2 GHz。
 * - 我将原先依赖 x86 汇编的 cpucycles() 替换为基于 clock_gettime(CLOCK_MONOTONIC_RAW)
 *   的高精度时间戳，并把时间戳按固定的 CPU 频率 (1200.0 MHz) 映射为 "等效周期数"。
 * - MEASURE 宏也改用这个等效周期计数来计算总耗时（微秒），从而能在不支持 rdtsc 的 CPU/虚拟化环境下工作。
 * - cycles_to_ms() 的换算也以固定 1200 MHz 为基准。
 */

static const double CPU_FIXED_MHZ = 1200.0; /* 1.2 GHz */

int compare_uint64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a, vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static double get_cpu_freq(void) {
    /* 尝试读取 /proc/cpuinfo；如果失败或不可信（虚拟化环境），
       我们将使用固定频率 CPU_FIXED_MHZ（单位 MHz）。 */
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp == NULL) return CPU_FIXED_MHZ;
    char buf[512];
    double freq = -1.0;
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strstr(buf, "cpu MHz") != NULL) {
            if (sscanf(buf, "cpu MHz\t: %lf", &freq) == 1) break;
        }
    }
    fclose(fp);
    if (freq <= 0.0) return CPU_FIXED_MHZ;
    /* 如果读取到的值和固定频率接近，还是使用固定频率以保证一致性 */
    return CPU_FIXED_MHZ;
}

static double get_total_memory(void) {
    struct sysinfo info;
    if (sysinfo(&info) != 0) return -1.0;
    return (double)info.totalram * info.mem_unit / (1024.0 * 1024.0 * 1024.0);
}

static const char *get_compiler_name(void) {
#ifdef __GNUC__
    return "GCC";
#elif defined(__clang__)
    return "Clang";
#elif defined(_MSC_VER)
    return "MSVC";
#else
    return "Unknown";
#endif
}

static void print_platform_info(double *cpu_freq_out) {
    struct utsname un;
    if (uname(&un) != 0) {
        *cpu_freq_out = -1.0;
        return;
    }
    double cpu_freq = get_cpu_freq();
    double total_mem = get_total_memory();
    *cpu_freq_out = cpu_freq;
    printf("=============================================================\n");
    printf("                      测试平台信息                            \n");
    printf("=============================================================\n");
    printf("操作系统内核版本: %s %s\n", un.sysname, un.release);
    printf("编译器          : %s %s\n", get_compiler_name(), __VERSION__);
    printf("CPU基础频率     : %.2f MHz (固定为虚拟平台频率)\n", cpu_freq);
    printf("系统总内存      : %.2f GB\n", (total_mem >= 0) ? total_mem : -1.0);
    printf("测试次数        : %d 次\n", TEST_ROUNDS);
    printf("=============================================================\n\n");
}

static void calc_stats(uint64_t *data, int len, double *avg, uint64_t *median, uint64_t *min, uint64_t *max) {
    if (len == 0 || data == NULL) return;
    *min = data[0];
    *max = data[0];
    uint64_t sum = 0;
    for (int i = 0; i < len; i++) {
        sum += data[i];
        if (data[i] < *min) *min = data[i];
        if (data[i] > *max) *max = data[i];
    }
    *avg = (double)sum / len;
    qsort(data, len, sizeof(uint64_t), compare_uint64);
    if (len % 2 == 0) *median = (data[len/2 - 1] + data[len/2]) / 2;
    else *median = data[len/2];
}

static double cycles_to_ms(uint64_t cycles, double cpu_freq_mhz) {
    if (cpu_freq_mhz <= 0) return -1.0;
    /* cycles / (MHz) => microseconds ; /1000 => milliseconds */
    return (double)cycles / (cpu_freq_mhz * 1000.0);
}

static int cmp_llu(const void *a, const void*b)
{
  if(*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if(*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
  qsort(l,llen,sizeof(unsigned long long),cmp_llu);

  if(llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}

static void delta(unsigned long long *l, size_t llen)
{
    unsigned int i;
    for(i = 0; i < llen - 1; i++) {
        l[i] = l[i+1] - l[i];
    }
}

/*
 * 在不支持 x86 rdtsc 的平台（如 ARM 或虚拟平台）上，使用 clock_gettime 获取纳秒时间戳，
 * 然后基于固定 CPU 频率（MHz）将其映射为等效的“周期数”。
 */
static unsigned long long cpucycles_from_clock(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    unsigned long long ns = (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
    /* cycles = ns * (MHz / 1000) */
    double cycles_d = (double)ns * (CPU_FIXED_MHZ / 1000.0);
    return (unsigned long long)cycles_d;
}

static void printfcomma (unsigned long long n)
{
    if (n < 1000) {
        printf("%llu", n);
        return;
    }
    printfcomma(n / 1000);
    printf (",%03llu", n % 1000);
}

static void printfalignedcomma (unsigned long long n, int len)
{
    unsigned long long ncopy = n;
    int i = 0;

    while (ncopy > 9) {
        len -= 1;
        ncopy /= 10;
        i += 1;  // to account for commas
    }
    i = i/3 - 1;  // to account for commas
    for (; i < len; i++) {
        printf(" ");
    }
    printfcomma(n);
}

static void display_result(double result_us, unsigned long long *l, size_t llen, unsigned long long mul, double cpu_freq_mhz)
{
    unsigned long long med;

    /* result_us currently is the TOTAL microseconds for the whole NTESTS loop */
    result_us /= NTESTS; /* avg microseconds per iteration */
    /* l contains cycle-like values (we filled them via cpucycles_from_clock), so compute deltas */
    delta(l, NTESTS + 1);
    med = median(l, llen);
    printf("avg. %11.2lf us (%2.6lf sec); median ", result_us, result_us / 1e6);
    printfalignedcomma(med, 12);
    printf(" cycles,  %5llux: ", mul);
    printfalignedcomma((unsigned long long)(mul*med), 12);
    printf(" cycles\n");
}

/* MEASURE 宏：用 cpucycles_from_clock 记录等效周期（基于固定 MHz），并计算耗时（微秒） */
#define MEASURE(TEXT, MUL, FNCALL)\
    do {\
    printf(TEXT);\
    unsigned long long startc = cpucycles_from_clock();\
    for(i = 0; i < NTESTS; i++) {\
        t[i] = cpucycles_from_clock();\
        FNCALL;\
    }\
    t[NTESTS] = cpucycles_from_clock();\
    unsigned long long total_cycles = t[NTESTS] - t[0];\
    /* total microseconds = total_cycles / cpu_mhz */\
    double total_us = (double)total_cycles / cpu_freq_mhz;\
    display_result(total_us, t, NTESTS, MUL, cpu_freq_mhz);\
    } while(0)

int main()
{
    double cpu_freq = 0.0;
    /* 强制使用虚拟平台固定频率 */
    cpu_freq = CPU_FIXED_MHZ;
    print_platform_info(&cpu_freq);
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char *m = malloc(SPX_MLEN);
    unsigned char *sm = malloc(SPX_BYTES + SPX_MLEN);
    unsigned char *mout = malloc(SPX_BYTES + SPX_MLEN);

    unsigned char fors_pk[SPX_FORS_PK_BYTES];
    unsigned char fors_m[SPX_FORS_MSG_BYTES];
    unsigned char fors_sig[SPX_FORS_BYTES];
    unsigned char addr[SPX_ADDR_BYTES];

    unsigned char wots_sig[SPX_WOTS_BYTES];
    unsigned char wots_m[SPX_N];
    unsigned char wots_pk[SPX_WOTS_PK_BYTES];

    unsigned long long smlen;
    unsigned long long mlen;
    unsigned long long t[NTESTS+1];
    uint64_t keypair_cycles[TEST_ROUNDS] = {0};
    uint64_t sign_cycles[TEST_ROUNDS] = {0};
    uint64_t verify_cycles[TEST_ROUNDS] = {0};
    double kp_avg_cy, sign_avg_cy, verify_avg_cy;
    uint64_t kp_med_cy, sign_med_cy, verify_med_cy;
    uint64_t kp_min_cy, sign_min_cy, verify_min_cy;
    uint64_t kp_max_cy, sign_max_cy, verify_max_cy;
    int i;

    randombytes(m, SPX_MLEN);
    randombytes(addr, SPX_ADDR_BYTES);

    printf("Parameters: n = %d, h = %d, d = %d, b = %d, k = %d, w = %d\n",
           SPX_N, SPX_FULL_HEIGHT, SPX_D, SPX_FORS_HEIGHT, SPX_FORS_TREES,
           SPX_WOTS_W);

    printf("Running %d iterations.\n", NTESTS);

    /* 把 cpu_freq 存为全局可用（用于 MEASURE 宏内计算） */
    double cpu_freq_mhz = cpu_freq;

    MEASURE("Generating keypair.. ", 1, crypto_sign_keypair(pk, sk));
    MEASURE("  - WOTS pk gen..    ", (1 << SPX_TREE_HEIGHT), wots_gen_pk(wots_pk, sk, pk, (uint32_t *) addr));
    MEASURE("Signing..            ", 1, crypto_sign(sm, &smlen, m, SPX_MLEN, sk));
    MEASURE("  - FORS signing..   ", 1, fors_sign(fors_sig, fors_pk, fors_m, sk, pk, (uint32_t *) addr));
    MEASURE("  - WOTS signing..   ", SPX_D, wots_sign(wots_sig, wots_m, sk, pk, (uint32_t *) addr));
    MEASURE("  - WOTS pk gen..    ", SPX_D * (1 << SPX_TREE_HEIGHT), wots_gen_pk(wots_pk, sk, pk, (uint32_t *) addr));
    MEASURE("Verifying..          ", 1, crypto_sign_open(mout, &mlen, sm, smlen, pk));

    printf("\n正在执行 %d 次详细统计测试...\n", TEST_ROUNDS);
    for (int j = 0; j < TEST_ROUNDS; j++) {
     unsigned long long start, end;
     start = cpucycles_from_clock();
     crypto_sign_keypair(pk, sk);
     end = cpucycles_from_clock();
     keypair_cycles[j] = end - start;
     start = cpucycles_from_clock();
     crypto_sign(sm, &smlen, m, SPX_MLEN, sk);
     end = cpucycles_from_clock();
     sign_cycles[j] = end - start;
     start = cpucycles_from_clock();
     crypto_sign_open(mout, &mlen, sm, smlen, pk);
     end = cpucycles_from_clock();
     verify_cycles[j] = end - start;
    }

    calc_stats(keypair_cycles, TEST_ROUNDS, &kp_avg_cy, &kp_med_cy, &kp_min_cy, &kp_max_cy);
    calc_stats(sign_cycles, TEST_ROUNDS, &sign_avg_cy, &sign_med_cy, &sign_min_cy, &sign_max_cy);
    calc_stats(verify_cycles, TEST_ROUNDS, &verify_avg_cy, &verify_med_cy, &verify_min_cy, &verify_max_cy);

    double kp_avg_ms = cycles_to_ms((uint64_t)kp_avg_cy, cpu_freq_mhz);
    double kp_med_ms = cycles_to_ms(kp_med_cy, cpu_freq_mhz);
    double kp_min_ms = cycles_to_ms(kp_min_cy, cpu_freq_mhz);
    double kp_max_ms = cycles_to_ms(kp_max_cy, cpu_freq_mhz);
    double sign_avg_ms = cycles_to_ms((uint64_t)sign_avg_cy, cpu_freq_mhz);
    double sign_med_ms = cycles_to_ms(sign_med_cy, cpu_freq_mhz);
    double sign_min_ms = cycles_to_ms(sign_min_cy, cpu_freq_mhz);
    double sign_max_ms = cycles_to_ms(sign_max_cy, cpu_freq_mhz);
    double verify_avg_ms = cycles_to_ms((uint64_t)verify_avg_cy, cpu_freq_mhz);
    double verify_med_ms = cycles_to_ms(verify_med_cy, cpu_freq_mhz);
    double verify_min_ms = cycles_to_ms(verify_min_cy, cpu_freq_mhz);
    double verify_max_ms = cycles_to_ms(verify_max_cy, cpu_freq_mhz);

    printf("=======================================================================\n");
    printf("              sphincs-shake256-128f 性能测试结果（周期数）    \n");
    printf("=======================================================================\n");
    printf("%-15s | %-12s | %-12s | %-12s | %-12s\n",
        "测试项", "平均值(周期)", "中位数(周期)", "最小值(周期)", "最大值(周期)");
    printf("-------------------------------------------------------------\n");
    printf("%-15s | %-12.0f | %-12lu | %-12lu | %-12lu\n",
        "密钥对生成", kp_avg_cy, kp_med_cy, kp_min_cy, kp_max_cy);
    printf("%-15s | %-12.0f | %-12lu | %-12lu | %-12lu\n",
        "签名", sign_avg_cy, sign_med_cy, sign_min_cy, sign_max_cy);
    printf("%-15s | %-12.0f | %-12lu | %-12lu | %-12lu\n",
        "验证", verify_avg_cy, verify_med_cy, verify_min_cy, verify_max_cy);
    printf("=======================================================================\n");

    printf("=======================================================================\n");
    printf("              sphincs-shake256-128f 性能测试结果（时间）      \n");
    printf("=======================================================================\n");
    printf("%-15s | %-12s | %-12s | %-12s | %-12s\n",
        "测试项", "平均值(ms)", "中位数(ms)", "最小值(ms)", "最大值(ms)");
    printf("-----------------------------------------------------------------------\n");
    if (cpu_freq_mhz > 0) {
     printf("%-15s | %-12.6f | %-12.6f | %-12.6f | %-12.6f\n",
         "密钥对生成", kp_avg_ms, kp_med_ms, kp_min_ms, kp_max_ms);
     printf("%-15s | %-12.6f | %-12.6f | %-12.6f | %-12.6f\n",
         "签名", sign_avg_ms, sign_med_ms, sign_min_ms, sign_max_ms);
     printf("%-15s | %-12.6f | %-12.6f | %-12.6f | %-12.6f\n",
         "验证", verify_avg_ms, verify_med_ms, verify_min_ms, verify_max_ms);
    } else {
     printf("%-15s | %-12s | %-12s | %-12s | %-12s\n",
         "密钥对生成", "N/A", "N/A", "N/A", "N/A");
     printf("%-15s | %-12s | %-12s | %-12s | %-12s\n",
         "签名", "N/A", "N/A", "N/A", "N/A");
     printf("%-15s | %-12s | %-12s | %-12s | %-12s\n",
         "验证", "N/A", "N/A", "N/A", "N/A");
     printf("\n⚠️  提示：CPU频率获取失败，无法换算时间（ms）\n");
    }
    printf("=======================================================================\n");

    printf("Signature size: %d (%.2f KiB)\n", SPX_BYTES, SPX_BYTES / 1024.0);
    printf("Public key size: %d (%.2f KiB)\n", SPX_PK_BYTES, SPX_PK_BYTES / 1024.0);
    printf("Secret key size: %d (%.2f KiB)\n", SPX_SK_BYTES, SPX_SK_BYTES / 1024.0);

    free(m);
    free(sm);
    free(mout);

    return 0;
}
