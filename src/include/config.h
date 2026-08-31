#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

typedef struct {
    char db_path[256];
    int page_size;
    bool color_enabled;
    int max_properties;
    int max_users;
    int max_string_len;
    int max_field_len;
    char data_dir[256];
    char users_file[256];
    char salts_file[256];
    char codes_file[256];
    char logged_in_file[256];
    char properties_file[256];
} Config;

int config_load(const char *filename, Config *config);
void config_set_defaults(Config *config);
void config_print(const Config *config);

#endif