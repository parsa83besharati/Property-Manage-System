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

// Lease management
void menu_lease_management(Database *db, const char *username);
void menu_create_lease(Database *db, const char *username);
void menu_view_leases(Database *db, const char *username);
void menu_lease_payments(Database *db, const char *username);
void menu_terminate_lease(Database *db, const char *username);

// Expense management
void menu_expense_management(Database *db, const char *username);
void menu_add_expense(Database *db, const char *username);
void menu_view_expenses(Database *db, const char *username);
void menu_expense_summary(Database *db, const char *username);

// Reports
void menu_reports(Database *db, const char *username);

#endif