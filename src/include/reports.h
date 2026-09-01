#ifndef REPORTS_H
#define REPORTS_H

#include "database.h"

int generate_rent_roll_report(Database *db, const char *filename);
int generate_expense_report(Database *db, const char *filename);
int generate_property_summary_report(Database *db, const char *filename);

#endif