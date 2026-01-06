#include <stdio.h>

extern int test_sym;
int main() {
    printf("val: %08x, at: %016llx\n", test_sym, (unsigned long long)&test_sym);
    return 0;//test_sym;
}