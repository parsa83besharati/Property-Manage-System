#ifndef USER_H
#define USER_H

#include "common.h"

typedef struct {
    User *users;
    int count;
    int capacity;
    char users_file[256];
    char salts_file[256];
} UserManager;

UserManager *user_manager_create(const char *users_file, const char *salts_file);
void user_manager_destroy(UserManager *um);
int user_manager_load(UserManager *um);
int user_manager_save(UserManager *um);
int user_manager_add(UserManager *um, const User *user);
User *user_manager_find_by_username(UserManager *um, const char *username);
int user_manager_update_password(UserManager *um, const char *username, const char *new_hash, const char *new_salt);
int user_manager_update_field(UserManager *um, const char *username, int field, const char *value);
void user_manager_list_all(UserManager *um);
int user_register(UserManager *um);
int user_login(UserManager *um, char *logged_in_username);
int user_change_password(UserManager *um, const char *username);
int user_edit_profile(UserManager *um, const char *username);
int validate_username(const char *username);
int validate_name(const char *name);
int username_exists(UserManager *um, const char *username);
void get_password_hidden(char *buffer, int maxlen);

#define USER_FIELD_FIRST_NAME 1
#define USER_FIELD_LAST_NAME 2
#define USER_FIELD_ID 3
#define USER_FIELD_PHONE 4
#define USER_FIELD_EMAIL 5

#endif