#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/utsname.h>  // 系统内核信息
#include <sys/sysinfo.h>  // 内存信息
#include <string.h>       // 字符串处理
#include <stdint.h>       // uint64_t 类型
#include <stddef.h>

#include "../api.h"
#include "../fors.h"
#include "../wots.h"
#include "../params.h"
#include "../rng.h"

#define SPX_MLEN 32
#define NTESTS 10
#define TEST_ROUNDS 20

// 架构判断宏
#if defined(__x86_64__) || defined(i386)
#define ARCH_X86 1
#elif defined(__aarch64__) || defined(__arm__)
#define ARCH_ARM 1
#else
#define ARCH_UNKNOWN 1
#endif

int compare_uint64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a, vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static double get_cpu_freq(void) {
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp == NULL) return -1.0;
    char buf[256];
    double freq = -1.0;
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        // 兼容x86的cpu MHz和Arm的BogoMIPS（BogoMIPS≈2×CPU频率MHz）
        if (strstr(buf, "cpu MHz") != NULL) {
            sscanf(buf, "cpu MHz\t: %lf", &freq);
            break;
        } else if (strstr(buf, "BogoMIPS") != NULL && freq < 0) {
            double bogomips;
            if (sscanf(buf, "BogoMIPS\t: %lf", &bogomips) == 1) {
                freq = bogomips / 2.0;  // 近似换算CPU频率
            }
        }
    }
    fclose(fp);
    return freq;
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

static const char *get_arch_name(void) {
#ifdef ARCH_X86
#if defined(__x86_64__)
    return "x86_64";
#else
    return "x86_32";
#endif
#elif defined ARCH_ARM
#if defined(__aarch64__)
    return "ARM64 (aarch64)";
#else
    return "ARM32 (armv7+)";
#endif
#else
    return "Unknown Architecture";
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
    printf("架构类型        : %s\n", get_arch_name());
    printf("编译器          : %s %s\n", get_compiler_name(), __VERSION__);
    printf("CPU基础频率     : %.2f MHz\n", (cpu_freq >= 0) ? cpu_freq : -1.0);
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

static double cycles_to_ms(uint64_t cycles, double cpu_freq) {
    if (cpu_freq <= 0) return -1.0;
    return (double)cycles / (cpu_freq * 1000.0);
}

static int cmp_llu(const void *a, const void*b) {
    if(*(unsigned long long *)a < *(unsigned long long *)b) return -1;
    if(*(unsigned long long *)a > *(unsigned long long *)b) return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen) {
    qsort(l, llen, sizeof(unsigned long long), cmp_llu);
    if(llen%2) return l[llen/2];
    else return (l[llen/2-1]+l[llen/2])/2;
}

static void delta(unsigned long long *l, size_t llen) {
    unsigned int i;
    for(i = 0; i < llen - 1; i++) {
        l[i] = l[i+1] - l[i];
    }
}

// Arm架构CPU周期读取（支持aarch64和armv7+）
#if defined(ARCH_ARM)
static inline void enable_pmccntr(void) {
    uint32_t val;
    // 读取PMCR寄存器，启用计数器
    __asm__ volatile("mrc p15, 0, %0, c9, c12, 0" : "=r"(val));
    val |= 1;  // 置位EN位，启用计数器
    __asm__ volatile("mcr p15, 0, %0, c9, c12, 0" : : "r"(val));
    // 清除计数器
    __asm__ volatile("mcr p15, 0, %0, c9, c13, 0" : : "r"(0));
}

static unsigned long long cpucycles(void) {
    static int initialized = 0;
    if (!initialized) {
        enable_pmccntr();
        initialized = 1;
    }
    unsigned long long cycles;
#if defined(__aarch64__)
    // Arm64读取PMCCNTR_EL0寄存器
    __asm__ volatile("mrs %0, pmccntr_el0" : "=r"(cycles));
#else
    // Arm32读取PMCCNTR寄存器
    uint32_t lo, hi;
    __asm__ volatile(
        "mrc p15, 0, %0, c9, c13, 0\n"  // 读取低32位
        "mrc p15, 0, %1, c9, c13, 1"    // 读取高32位（若支持）
        : "=r"(lo), "=r"(hi)
    );
    cycles = ((unsigned long long)hi << 32) | lo;
#endif
    return cycles;
}
#elif defined(ARCH_X86)
// 保留原x86实现，兼容双向编译
static unsigned long long cpucycles(void) {
    unsigned long long result;
    __asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
        : "=a" (result) ::  "%rdx");
    return result;
}
#endif

static void printfcomma(unsigned long long n) {
    if (n < 1000) {
        printf("%llu", n);
        return;
    }
    printfcomma(n / 1000);
    printf(",%03llu", n % 1000);
}

static void printfalignedcomma(unsigned long long n, int len) {
    unsigned long long ncopy = n;
    int i = 0;
    while (ncopy > 9) {
        len -= 1;
        ncopy /= 10;
        i += 1;
    }
    i = i/3 - 1;
    for (; i < len; i++) {
        printf(" ");
    }
    printfcomma(n);
}

static void display_result(double result, unsigned long long *l, size_t llen, unsigned long long mul) {
    unsigned long long med;
    result /= NTESTS;
    delta(l, NTESTS + 1);
    med = median(l, llen);
    printf("avg. %11.2lf us (%2.2lf sec); median ", result, result / 1e6);
    printfalignedcomma(med, 12);
    printf(" cycles,  %5llux: ", mul);
    printfalignedcomma(mul*med, 12);
    printf(" cycles\n");
}

#define MEASURE(TEXT, MUL, FNCALL)\
    printf(TEXT);\
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);\
    for(i = 0; i < NTESTS; i++) {\
        t[i] = cpucycles();\
        FNCALL;\
    }\
    t[NTESTS] = cpucycles();\
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);\
    result = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;\
    display_result(result, t, NTESTS, MUL);

int main() {
    double cpu_freq;
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
    struct timespec start, stop;
    double result;
    int i;

    randombytes(m, SPX_MLEN);
    randombytes(addr, SPX_ADDR_BYTES);

    printf("Parameters: n = %d, h = %d, d = %d, b = %d, k = %d, w = %d\n",
           SPX_N, SPX_FULL_HEIGHT, SPX_D, SPX_FORS_HEIGHT, SPX_FORS_TREES,
           SPX_WOTS_W);

    printf("Running %d iterations.\n", NTESTS);

    MEASURE("Generating keypair.. ", 1, crypto_sign_keypair(pk, sk));
    MEASURE("  - WOTS pk gen..    ", (1 << SPX_TREE_HEIGHT), wots_gen_pk(wots_pk, sk, pk, (uint32_t *) addr));
    MEASURE("Signing..            ", 1, crypto_sign(sm, &smlen, m, SPX_MLEN, sk));
    MEASURE("  - FORS signing..   ", 1, fors_sign(fors_sig, fors_pk, fors_m, sk, pk, (uint32_t *) addr));
    MEASURE("  - WOTS signing..   ", SPX_D, wots_sign(wots_sig, wots_m, sk, pk, (uint32_t *) addr));
    MEASURE("  - WOTS pk gen..    ", SPX_D * (1 << SPX_TREE_HEIGHT), wots_gen_pk(wots_pk, sk, pk, (uint32_t *) addr));
    MEASURE("Verifying..          ", 1, crypto_sign_open(mout, &mlen, sm, smlen, pk));

    printf("\n正在执行 %d 次详细统计测试...\n", TEST_ROUNDS);
    for (int j = 0; j < TEST_ROUNDS; j++) {
        uint64_t start_cy, end_cy;
        start_cy = cpucycles();
        crypto_sign_keypair(pk, sk);
        end_cy = cpucycles();
        keypair_cycles[j] = end_cy - start_cy;

        start_cy = cpucycles();
        crypto_sign(sm, &smlen, m, SPX_MLEN, sk);
        end_cy = cpucycles();
        sign_cycles[j] = end_cy - start_cy;

        start_cy = cpucycles();
        crypto_sign_open(mout, &mlen, sm, smlen, pk);
        end_cy = cpucycles();
        verify_cycles[j] = end_cy - start_cy;
    }

    double kp_avg_cy, sign_avg_cy, verify_avg_cy;
    uint64_t kp_med_cy, sign_med_cy, verify_med_cy;
    uint64_t kp_min_cy, sign_min_cy, verify_min_cy;
    uint64_t kp_max_cy, sign_max_cy, verify_max_cy;

    calc_stats(keypair_cycles, TEST_ROUNDS, &kp_avg_cy, &kp_med_cy, &kp_min_cy, &kp_max_cy);
    calc_stats(sign_cycles, TEST_ROUNDS, &sign_avg_cy, &sign_med_cy, &sign_min_cy, &sign_max_cy);
    calc_stats(verify_cycles, TEST_ROUNDS, &verify_avg_cy, &verify_med_cy, &verify_min_cy, &verify_max_cy);

    double kp_avg_ms = cycles_to_ms((uint64_t)kp_avg_cy, cpu_freq);
    double kp_med_ms = cycles_to_ms(kp_med_cy, cpu_freq);
    double kp_min_ms = cycles_to_ms(kp_min_cy, cpu_freq);
    double kp_max_ms = cycles_to_ms(kp_max_cy, cpu_freq);
    double sign_avg_ms = cycles_to_ms((uint64_t)sign_avg_cy, cpu_freq);
    double sign_med_ms = cycles_to_ms(sign_med_cy, cpu_freq);
    double sign_min_ms = cycles_to_ms(sign_min_cy, cpu_freq);
    double sign_max_ms = cycles_to_ms(sign_max_cy, cpu_freq);
    double verify_avg_ms = cycles_to_ms((uint64_t)verify_avg_cy, cpu_freq);
    double verify_med_ms = cycles_to_ms(verify_med_cy, cpu_freq);
    double verify_min_ms = cycles_to_ms(verify_min_cy, cpu_freq);
    double verify_max_ms = cycles_to_ms(verify_max_cy, cpu_freq);

    printf("=======================================================================\n");
    printf("              sphincs-haraka-128f 性能测试结果（周期数）    \n");
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
    printf("              sphincs-haraka-128f 性能测试结果（时间）      \n");
    printf("=======================================================================\n");
    printf("%-15s | %-12s | %-12s | %-12s | %-12s\n",
        "测试项", "平均值(ms)", "中位数(ms)", "最小值(ms)", "最大值(ms)");
    printf("-----------------------------------------------------------------------\n");
    if (cpu_freq > 0) {
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