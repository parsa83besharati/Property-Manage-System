#include "config.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    Config config;
    int r = config_load("config.ini", &config);
    printf("config_load returned: %d\n", r);
    printf("db_path: %s\n", config.db_path);
    printf("page_size: %d\n", config.page_size);
    return 0;
}