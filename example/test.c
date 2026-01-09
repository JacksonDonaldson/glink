extern long long foo;

typedef int (*printf_t)(const char *format, ...);
extern printf_t printf;

int main() {
    printf("f at: %16llx", foo);
    return 0;//test_sym;
}