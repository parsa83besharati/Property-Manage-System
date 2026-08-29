#ifndef PROPERTY_H
#define PROPERTY_H

#include "common.h"

typedef struct {
    Property *properties;
    int count;
    int capacity;
    char filename[256];
} PropertyManager;

PropertyManager *property_manager_create(const char *filename);
void property_manager_destroy(PropertyManager *pm);
int property_manager_load(PropertyManager *pm);
int property_manager_save(PropertyManager *pm);
int property_manager_add(PropertyManager *pm, const Property *prop);
int property_manager_delete(PropertyManager *pm, const char *code);
Property *property_manager_find(PropertyManager *pm, const char *code);
void property_manager_list_all(PropertyManager *pm);
void property_manager_list_by_type(PropertyManager *pm, PropertyType ptype, PropertyAction action);
void property_manager_list_by_district(PropertyManager *pm, int district);
void property_manager_list_by_location(PropertyManager *pm, Location location);
void property_manager_list_by_price_range(PropertyManager *pm, double min, double max);
int property_count_by_type(PropertyManager *pm, PropertyType ptype, PropertyAction action);
void property_print(const Property *prop);
void property_print_short(const Property *prop);
int input_property(Property *prop, const char *username);
int input_property_field_int(const char *prompt, int min, int max, int *out);
int input_property_field_double(const char *prompt, double min, double max, double *out);
int input_property_field_string(const char *prompt, char *out, int maxlen, int (*validator)(const char *));
int input_property_field_enum(const char *prompt, const char *options[], int count, int *out);
Location input_location(void);
ResidentialType input_residential_type(void);
CommercialType input_commercial_type(void);
LandType input_land_type(void);
Temperature input_temperature(void);
YesNo input_yes_no(const char *prompt);
const char *location_to_string(Location loc);
const char *residential_type_to_string(ResidentialType type);
const char *commercial_type_to_string(CommercialType type);
const char *land_type_to_string(LandType type);
const char *temperature_to_string(Temperature temp);
const char *yes_no_to_string(YesNo yn);
const char *property_type_to_string(PropertyType type);
const char *property_action_to_string(PropertyAction action);

#endif