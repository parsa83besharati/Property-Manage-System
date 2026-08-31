#include "config.h"
#include <stdio.h>
#include <string.h>

int test_config_defaults(void) {
    Config config;
    config_set_defaults(&config);
    
    if (strcmp(config.db_path, "data/property_manage.db") != 0) return 1;
    if (config.page_size != 10) return 1;
    if (config.color_enabled != true) return 1;
    if (config.max_properties != 10000) return 1;
    if (config.max_users != 1000) return 1;
    return 0;
}

int test_config_load(void) {
    Config config;
    int r = config_load("config.ini", &config);
    printf("config_load returned: %d\n", r);
    printf("db_path: '%s'\n", config.db_path);
    printf("page_size: %d\n", config.page_size);
    if (r != 1) { printf("fail: r != 1\n"); return 1; }
    if (strcmp(config.db_path, "data/property_manage.db") != 0) { printf("fail: db_path mismatch\n"); return 1; }
    if (config.page_size != 10) { printf("fail: page_size mismatch\n"); return 1; }
    return 0;
}

int main(void) {
    if (test_config_defaults() != 0) {
        printf("FAIL: test_config_defaults\n");
        return 1;
    }
    if (test_config_load() != 0) {
        printf("FAIL: test_config_load\n");
        return 1;
    }
    printf("All config tests passed\n");
    return 0;
}