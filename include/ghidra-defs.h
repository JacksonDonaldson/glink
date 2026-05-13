
enum ADDRESS_TYPE {
    address_type_relocatable,
    address_type_external
};

enum symbol_type {
    symbol_type_label = 0,
    symbol_type_library=1,
    symbol_type_namespace = 3,
    symbol_type_class = 4,
    symbol_type_function = 5,
    symbol_type_parameter = 6,
    symbol_type_local = 7,
    symbol_type_global = 8
};