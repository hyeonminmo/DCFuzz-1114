#include <stdint.h>
#include <stdio.h>

#ifndef DOMINATOR_NUM
#define DOMINATOR_NUM 1
#endif

const uint64_t __dominator_num = DOMINATOR_NUM;
uint64_t __dominator_counts[DOMINATOR_NUM];
unsigned char __dominator_seen[DOMINATOR_NUM];

__attribute__((destructor))
static void __dominator_dump(void) {
    uint64_t total = __dominator_num;
    uint64_t covered = 0;
    uint64_t exec_total = 0;

    fprintf(stderr, "=== dominator coverage summary ===\n");

    for (uint64_t i = 0; i < total; ++i) {
        uint64_t count = __dominator_counts[i];
        unsigned seen = (__dominator_seen[i] != 0);

        if (seen) {
            covered++;
        }
        exec_total += count;

        fprintf(stderr,
                "DOM_ID=%llu EXEC=%llu SEEN=%u\n",
                (unsigned long long)i,
                (unsigned long long)count,
                seen);
    }

    fprintf(stderr, "DOM_TOTAL=%llu\n", (unsigned long long)total);
    fprintf(stderr, "DOM_COVERED=%llu\n", (unsigned long long)covered);
    fprintf(stderr, "DOM_EXEC_TOTAL=%llu\n", (unsigned long long)exec_total);
}