#ifndef MENU_H
#define MENU_H

#include "common.h"
#include "database.h"

void menu_entry(Database *db);
void menu_main(Database *db, const char *username);
void menu_add_property(Database *db, const char *username);
void menu_delete_property(Database *db, const char *username);
void menu_search_properties(Database *db, const char *username);
void menu_user_settings(Database *db, const char *username);
void menu_admin(Database *db);

#endif