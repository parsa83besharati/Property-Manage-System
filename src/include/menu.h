#ifndef MENU_H
#define MENU_H

#include "common.h"
#include "property.h"
#include "user.h"

void menu_entry(UserManager *um, PropertyManager *pm);
void menu_main(UserManager *um, PropertyManager *pm, const char *username);
void menu_add_property(UserManager *um, PropertyManager *pm, const char *username);
void menu_delete_property(PropertyManager *pm, const char *username);
void menu_reports(PropertyManager *pm);
void menu_user_settings(UserManager *um, const char *username);
void menu_admin(UserManager *um, PropertyManager *pm);
void menu_property_type_select(PropertyType *ptype, PropertyAction *action);

#endif