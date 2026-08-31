#ifndef EXPORT_H
#define EXPORT_H

#include "database.h"

int export_users_to_csv(Database *db, const char *filename);
int export_properties_to_csv(Database *db, const char *filename);
int export_all_to_csv(Database *db, const char *users_file, const char *properties_file);

#endif