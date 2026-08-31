#ifndef USER_H
#define USER_H

#include "common.h"
#include "database.h"

int user_register(Database *db);
int user_login(Database *db, char *logged_in_username);
int user_change_password(Database *db, const char *username);
int user_edit_profile(Database *db, const char *username);
int validate_username(const char *username);
int validate_name(const char *name);
int username_exists(Database *db, const char *username);
void get_password_hidden(char *buffer, int maxlen);

#define USER_FIELD_FIRST_NAME 1
#define USER_FIELD_LAST_NAME 2
#define USER_FIELD_ID 3
#define USER_FIELD_PHONE 4
#define USER_FIELD_EMAIL 5

#endif