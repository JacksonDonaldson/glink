extern long long foo;
extern const char* foo_string;

typedef int (printf_t)(const char *format, ...);
extern printf_t printf;

int new_main() {
    printf("f at: %16llx %s", foo, foo_string);
    return 0;//test_sym;
}