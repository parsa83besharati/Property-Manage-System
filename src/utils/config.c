#include "config.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>



static void parse_line(char *line, char **key, char **value) {
    char *eq = strchr(line, '=');
    if (!eq) return;
    *eq = '\0';
    *key = line;
    *value = eq + 1;
    
    char *start = *key;
    while (isspace((unsigned char)*start)) start++;
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    if (start != *key) {
        memmove(*key, start, end - start + 2);
    }
    
    char *vstart = *value;
    while (isspace((unsigned char)*vstart)) vstart++;
    char *vend = vstart + strlen(vstart) - 1;
    while (vend > vstart && isspace((unsigned char)*vend)) vend--;
    *(vend + 1) = '\0';
    if (vstart != *value) {
        memmove(*value, vstart, vend - vstart + 2);
    }
    
    if ((*value)[0] == '"' && (*value)[strlen(*value) - 1] == '"') {
        (*value)[strlen(*value) - 1] = '\0';
        (*value)++;
    }
}

void config_set_defaults(Config *config) {
    strcpy(config->db_path, "data/property_manage.db");
    config->page_size = 10;
    config->color_enabled = true;
    config->max_properties = 10000;
    config->max_users = 1000;
    config->max_string_len = 500;
    config->max_field_len = 50;
    strcpy(config->data_dir, "data/");
    strcpy(config->users_file, "data/users.dat");
    strcpy(config->salts_file, "data/salts.dat");
    strcpy(config->codes_file, "data/codes.dat");
    strcpy(config->logged_in_file, "data/logged_in.dat");
    strcpy(config->properties_file, "data/properties.dat");
}

int config_load(const char *filename, Config *config) {
    config_set_defaults(config);
    
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        return 0;
    }
    
    char line[512];
    char current_section[64] = "";
    
    while (fgets(line, sizeof(line), fp)) {
        char *start = line;
        while (isspace((unsigned char)*start)) start++;
        if (*start == '\0' || *start == '#' || *start == ';') continue;
        
        char *end = start + strlen(start) - 1;
        while (end > start && isspace((unsigned char)*end)) end--;
        *(end + 1) = '\0';
        
        if (start[0] == '[' && start[strlen(start) - 1] == ']') {
            start[strlen(start) - 1] = '\0';
            strcpy(current_section, start + 1);
            continue;
        }
        
        char *key, *value;
        parse_line(start, &key, &value);
        if (!key || !value) continue;
        
        if (strcmp(current_section, "database") == 0) {
            if (strcmp(key, "path") == 0) strncpy(config->db_path, value, sizeof(config->db_path) - 1);
        } else if (strcmp(current_section, "ui") == 0) {
            if (strcmp(key, "page_size") == 0) config->page_size = atoi(value);
            else if (strcmp(key, "color_enabled") == 0) config->color_enabled = (strcmp(value, "true") == 0);
        } else if (strcmp(current_section, "limits") == 0) {
            if (strcmp(key, "max_properties") == 0) config->max_properties = atoi(value);
            else if (strcmp(key, "max_users") == 0) config->max_users = atoi(value);
            else if (strcmp(key, "max_string_len") == 0) config->max_string_len = atoi(value);
            else if (strcmp(key, "max_field_len") == 0) config->max_field_len = atoi(value);
        } else if (strcmp(current_section, "paths") == 0) {
            if (strcmp(key, "data_dir") == 0) strncpy(config->data_dir, value, sizeof(config->data_dir) - 1);
            else if (strcmp(key, "users_file") == 0) strncpy(config->users_file, value, sizeof(config->users_file) - 1);
            else if (strcmp(key, "salts_file") == 0) strncpy(config->salts_file, value, sizeof(config->salts_file) - 1);
            else if (strcmp(key, "codes_file") == 0) strncpy(config->codes_file, value, sizeof(config->codes_file) - 1);
            else if (strcmp(key, "logged_in_file") == 0) strncpy(config->logged_in_file, value, sizeof(config->logged_in_file) - 1);
            else if (strcmp(key, "properties_file") == 0) strncpy(config->properties_file, value, sizeof(config->properties_file) - 1);
        }
    }
    
    fclose(fp);
    return 1;
}

void config_print(const Config *config) {
    printf("=== Configuration ===\n");
    printf("Database: %s\n", config->db_path);
    printf("Page size: %d\n", config->page_size);
    printf("Color: %s\n", config->color_enabled ? "enabled" : "disabled");
    printf("Max properties: %d\n", config->max_properties);
    printf("Max users: %d\n", config->max_users);
    printf("Data dir: %s\n", config->data_dir);
    printf("=======================\n");
}