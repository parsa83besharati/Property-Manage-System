#ifndef DATABASE_H
#define DATABASE_H

#include "common.h"
#include "sqlite3.h"

typedef struct {
    sqlite3 *db;
    char db_path[256];
} Database;

Database *database_open(const char *path);
void database_close(Database *db);
int database_init_schema(Database *db);

// User operations
int db_user_create(Database *db, const User *user);
User *db_user_find_by_username(Database *db, const char *username);
int db_user_update_password(Database *db, const char *username, const char *hash, const char *salt);
int db_user_update_field(Database *db, const char *username, int field, const char *value);
int db_user_list_all(Database *db, User **users, int *count);
int db_user_count(Database *db);
int db_user_set_role(Database *db, const char *username, UserRole role);
UserRole db_user_get_role(Database *db, const char *username);

// Property operations
int db_property_create(Database *db, const Property *prop);
Property *db_property_find_by_code(Database *db, const char *code);
int db_property_delete(Database *db, const char *code);
int db_property_list_all(Database *db, Property **props, int *count);
int db_property_list_by_type(Database *db, PropertyType ptype, PropertyAction action, Property **props, int *count);
int db_property_list_by_district(Database *db, int district, Property **props, int *count);
int db_property_list_by_location(Database *db, Location location, Property **props, int *count);
int db_property_list_by_price_range(Database *db, double min, double max, Property **props, int *count);
int db_property_count_by_type(Database *db, PropertyType ptype, PropertyAction action);
int db_property_list_paginated(Database *db, const char *where_clause, const char *order_by, int limit, int offset, Property **props, int *count);
int db_property_count_filtered(Database *db, const char *where_clause);

// Migration
int database_migrate_from_files(Database *db, const char *users_file, const char *properties_file);

#endif