#include "property.h"
#include "sha256.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void ensure_data_dir(void) {
    MKDIR("data");
}

static int ensure_capacity(PropertyManager *pm) {
    if (pm->count >= pm->capacity) {
        int new_capacity = pm->capacity == 0 ? 100 : pm->capacity * 2;
        Property *new_props = realloc(pm->properties, new_capacity * sizeof(Property));
        if (!new_props) return 0;
        pm->properties = new_props;
        pm->capacity = new_capacity;
    }
    return 1;
}

PropertyManager *property_manager_create(const char *filename) {
    ensure_data_dir();
    
    PropertyManager *pm = malloc(sizeof(PropertyManager));
    if (!pm) return NULL;
    pm->properties = NULL;
    pm->count = 0;
    pm->capacity = 0;
    strncpy(pm->filename, filename, sizeof(pm->filename) - 1);
    pm->filename[sizeof(pm->filename) - 1] = '\0';
    return pm;
}

void property_manager_destroy(PropertyManager *pm) {
    if (pm) {
        free(pm->properties);
        free(pm);
    }
}

static void property_serialize(const Property *prop, FILE *fp) {
    fprintf(fp, "%s|%d|%s|%d|%d|%d|%d|%d|%.2f|%d|%.2f|%s|%d|%d|%.2f|%d|%d|%.2f|%d|%.2f|%d|%d|%d|%.2f|%.2f|%.2f|%s|%s|%d\n",
        prop->code,
        prop->district,
        prop->address,
        prop->location,
        prop->ptype,
        prop->action,
        prop->subtype.res_type,
        prop->build_age,
        prop->floor_area,
        prop->floor,
        prop->land_area,
        prop->owner_phone,
        prop->bedrooms,
        prop->rooms,
        prop->tax_rate,
        prop->elevator,
        prop->basement,
        prop->basement_area,
        prop->balcony,
        prop->balcony_area,
        prop->parkings,
        prop->phones,
        prop->temperature,
        prop->sell_price,
        prop->base_price,
        prop->monthly_price,
        prop->date,
        prop->username,
        prop->active
    );
}

static int property_deserialize(Property *prop, FILE *fp) {
    char line[4096];
    if (!fgets(line, sizeof(line), fp)) return 0;
    trim_newline(line);
    
    char *tokens[30];
    int token_count = 0;
    char *token = strtok(line, "|");
    while (token && token_count < 30) {
        tokens[token_count++] = token;
        token = strtok(NULL, "|");
    }
    
    if (token_count < 29) return 0;
    
    int idx = 0;
    strncpy(prop->code, tokens[idx++], MAX_FIELD_LEN - 1);
    prop->district = atoi(tokens[idx++]);
    strncpy(prop->address, tokens[idx++], MAX_STRING_LEN - 1);
    prop->location = (Location)atoi(tokens[idx++]);
    prop->ptype = (PropertyType)atoi(tokens[idx++]);
    prop->action = (PropertyAction)atoi(tokens[idx++]);
    prop->subtype.res_type = (ResidentialType)atoi(tokens[idx++]);
    prop->build_age = atoi(tokens[idx++]);
    prop->floor_area = atof(tokens[idx++]);
    prop->floor = atoi(tokens[idx++]);
    prop->land_area = atof(tokens[idx++]);
    strncpy(prop->owner_phone, tokens[idx++], MAX_FIELD_LEN - 1);
    prop->bedrooms = atoi(tokens[idx++]);
    prop->rooms = atoi(tokens[idx++]);
    prop->tax_rate = atof(tokens[idx++]);
    prop->elevator = (YesNo)atoi(tokens[idx++]);
    prop->basement = (YesNo)atoi(tokens[idx++]);
    prop->basement_area = atof(tokens[idx++]);
    prop->balcony = (YesNo)atoi(tokens[idx++]);
    prop->balcony_area = atof(tokens[idx++]);
    prop->parkings = atoi(tokens[idx++]);
    prop->phones = atoi(tokens[idx++]);
    prop->temperature = (Temperature)atoi(tokens[idx++]);
    prop->sell_price = atof(tokens[idx++]);
    prop->base_price = atof(tokens[idx++]);
    prop->monthly_price = atof(tokens[idx++]);
    strncpy(prop->date, tokens[idx++], MAX_FIELD_LEN - 1);
    strncpy(prop->username, tokens[idx++], MAX_FIELD_LEN - 1);
    prop->active = atoi(tokens[idx++]);
    
    return 1;
}

int property_manager_load(PropertyManager *pm) {
    FILE *fp = fopen(pm->filename, "r");
    if (!fp) return 0;
    
    Property prop;
    while (property_deserialize(&prop, fp)) {
        if (!ensure_capacity(pm)) {
            fclose(fp);
            return 0;
        }
        pm->properties[pm->count++] = prop;
    }
    
    fclose(fp);
    return 1;
}

int property_manager_save(PropertyManager *pm) {
    FILE *fp = fopen(pm->filename, "w");
    if (!fp) return 0;
    
    for (int i = 0; i < pm->count; i++) {
        property_serialize(&pm->properties[i], fp);
    }
    
    fclose(fp);
    return 1;
}

int property_manager_add(PropertyManager *pm, const Property *prop) {
    if (!ensure_capacity(pm)) return 0;
    
    if (property_manager_find(pm, prop->code)) return 0;
    
    pm->properties[pm->count++] = *prop;
    return property_manager_save(pm);
}

int property_manager_delete(PropertyManager *pm, const char *code) {
    for (int i = 0; i < pm->count; i++) {
        if (strcmp(pm->properties[i].code, code) == 0) {
            pm->properties[i].active = false;
            return property_manager_save(pm);
        }
    }
    return 0;
}

Property *property_manager_find(PropertyManager *pm, const char *code) {
    for (int i = 0; i < pm->count; i++) {
        if (strcmp(pm->properties[i].code, code) == 0 && pm->properties[i].active) {
            return &pm->properties[i];
        }
    }
    return NULL;
}

void property_manager_list_all(PropertyManager *pm) {
    int found = 0;
    for (int i = 0; i < pm->count; i++) {
        if (pm->properties[i].active) {
            property_print_short(&pm->properties[i]);
            found = 1;
        }
    }
    if (!found) {
        printf("No properties found.\n");
    }
}

void property_manager_list_by_type(PropertyManager *pm, PropertyType ptype, PropertyAction action) {
    int found = 0;
    for (int i = 0; i < pm->count; i++) {
        if (pm->properties[i].active && 
            pm->properties[i].ptype == ptype && 
            pm->properties[i].action == action) {
            property_print_short(&pm->properties[i]);
            found = 1;
        }
    }
    if (!found) {
        printf("No properties found for this type.\n");
    }
}

void property_manager_list_by_district(PropertyManager *pm, int district) {
    int found = 0;
    for (int i = 0; i < pm->count; i++) {
        if (pm->properties[i].active && pm->properties[i].district == district) {
            property_print_short(&pm->properties[i]);
            found = 1;
        }
    }
    if (!found) {
        printf("No properties found in district %d.\n", district);
    }
}

void property_manager_list_by_location(PropertyManager *pm, Location location) {
    int found = 0;
    for (int i = 0; i < pm->count; i++) {
        if (pm->properties[i].active && pm->properties[i].location == location) {
            property_print_short(&pm->properties[i]);
            found = 1;
        }
    }
    if (!found) {
        printf("No properties found in this location.\n");
    }
}

void property_manager_list_by_price_range(PropertyManager *pm, double min, double max) {
    int found = 0;
    for (int i = 0; i < pm->count; i++) {
        if (!pm->properties[i].active) continue;
        
        double price = (pm->properties[i].action == PROP_ACTION_SELL) ? 
            pm->properties[i].sell_price : pm->properties[i].monthly_price;
        
        if (price >= min && price <= max) {
            property_print_short(&pm->properties[i]);
            found = 1;
        }
    }
    if (!found) {
        printf("No properties found in price range %.2f - %.2f.\n", min, max);
    }
}

int property_count_by_type(PropertyManager *pm, PropertyType ptype, PropertyAction action) {
    int count = 0;
    for (int i = 0; i < pm->count; i++) {
        if (pm->properties[i].active && 
            pm->properties[i].ptype == ptype && 
            pm->properties[i].action == action) {
            count++;
        }
    }
    return count;
}

void property_print(const Property *prop) {
    printf("\n--- Property Details ---\n");
    printf("Code: %s\n", prop->code);
    printf("Type: %s %s\n", property_action_to_string(prop->action), property_type_to_string(prop->ptype));
    
    switch (prop->ptype) {
        case PROP_TYPE_RESIDENTIAL:
            printf("Subtype: %s\n", residential_type_to_string(prop->subtype.res_type));
            break;
        case PROP_TYPE_COMMERCIAL:
            printf("Subtype: %s\n", commercial_type_to_string(prop->subtype.com_type));
            break;
        case PROP_TYPE_LAND:
            printf("Subtype: %s\n", land_type_to_string(prop->subtype.land_type));
            break;
    }
    
    printf("District: %d\n", prop->district);
    printf("Address: %s\n", prop->address);
    printf("Location: %s\n", location_to_string(prop->location));
    printf("Build Age: %d years\n", prop->build_age);
    printf("Floor Area: %.2f m²\n", prop->floor_area);
    printf("Floor: %d\n", prop->floor);
    printf("Land Area: %.2f m²\n", prop->land_area);
    printf("Owner Phone: %s\n", prop->owner_phone);
    
    if (prop->ptype == PROP_TYPE_RESIDENTIAL) {
        printf("Bedrooms: %d\n", prop->bedrooms);
    } else if (prop->ptype == PROP_TYPE_COMMERCIAL) {
        printf("Rooms: %d\n", prop->rooms);
    }
    
    printf("Tax Rate: %.2f%%\n", prop->tax_rate);
    printf("Elevator: %s\n", yes_no_to_string(prop->elevator));
    printf("Basement: %s\n", yes_no_to_string(prop->basement));
    if (prop->basement == YES_NO_YES) {
        printf("Basement Area: %.2f m²\n", prop->basement_area);
    }
    printf("Balcony: %s\n", yes_no_to_string(prop->balcony));
    if (prop->balcony == YES_NO_YES) {
        printf("Balcony Area: %.2f m²\n", prop->balcony_area);
    }
    printf("Parkings: %d\n", prop->parkings);
    printf("Phones: %d\n", prop->phones);
    printf("Temperature: %s\n", temperature_to_string(prop->temperature));
    
    if (prop->action == PROP_ACTION_SELL) {
        printf("Sell Price: %.2f Rials\n", prop->sell_price);
    } else {
        printf("Base Price: %.2f Rials\n", prop->base_price);
        printf("Monthly Price: %.2f Rials\n", prop->monthly_price);
    }
    
    printf("Date: %s\n", prop->date);
    printf("Registered by: %s\n", prop->username);
    printf("Status: %s\n", prop->active ? "Active" : "Inactive");
    printf("------------------------\n");
}

void property_print_short(const Property *prop) {
    double price = (prop->action == PROP_ACTION_SELL) ? prop->sell_price : prop->monthly_price;
    printf("[%s] %s %s | District: %d | %s | %.2f Rials | %s\n",
        prop->code,
        property_action_to_string(prop->action),
        property_type_to_string(prop->ptype),
        prop->district,
        location_to_string(prop->location),
        price,
        prop->active ? "Active" : "Inactive"
    );
}

int input_property_field_int(const char *prompt, int min, int max, int *out) {
    char input[100];
    while (1) {
        printf("%s [%d-%d]: ", prompt, min, max);
        safe_gets(input, sizeof(input));
        if (validate_int_range(input, min, max, out)) return 1;
        printf("Invalid input. Please enter a number between %d and %d.\n", min, max);
    }
}

int input_property_field_double(const char *prompt, double min, double max, double *out) {
    char input[100];
    while (1) {
        printf("%s [%.2f-%.2f]: ", prompt, min, max);
        safe_gets(input, sizeof(input));
        if (validate_double_range(input, min, max, out)) return 1;
        printf("Invalid input. Please enter a number between %.2f and %.2f.\n", min, max);
    }
}

int input_property_field_string(const char *prompt, char *out, int maxlen, int (*validator)(const char *)) {
    char input[MAX_STRING_LEN];
    while (1) {
        printf("%s: ", prompt);
        safe_gets(input, sizeof(input));
        if (strlen(input) == 0) {
            printf("Input cannot be empty.\n");
            continue;
        }
        if (strlen(input) >= maxlen) {
            printf("Input too long (max %d characters).\n", maxlen - 1);
            continue;
        }
        if (validator && !validator(input)) {
            printf("Invalid format.\n");
            continue;
        }
        strncpy(out, input, maxlen - 1);
        out[maxlen - 1] = '\0';
        return 1;
    }
}

int input_property_field_enum(const char *prompt, const char *options[], int count, int *out) {
    char input[100];
    while (1) {
        printf("%s (", prompt);
        for (int i = 0; i < count; i++) {
            printf("%s", options[i]);
            if (i < count - 1) printf(", ");
        }
        printf("): ");
        safe_gets(input, sizeof(input));
        capitalize_words(input);
        
        for (int i = 0; i < count; i++) {
            if (strcasecmp(input, options[i]) == 0) {
                *out = i;
                return 1;
            }
        }
        printf("Invalid option. Please choose from the list.\n");
    }
}

Location input_location(void) {
    const char *options[] = {"North", "South", "East", "West"};
    int choice;
    input_property_field_enum("Location", options, 4, &choice);
    return (Location)choice;
}

ResidentialType input_residential_type(void) {
    const char *options[] = {"Apartment", "Villa"};
    int choice;
    input_property_field_enum("Type", options, 2, &choice);
    return (ResidentialType)choice;
}

CommercialType input_commercial_type(void) {
    const char *options[] = {"Official", "Position"};
    int choice;
    input_property_field_enum("Type", options, 2, &choice);
    return (CommercialType)choice;
}

LandType input_land_type(void) {
    const char *options[] = {"Farm", "City"};
    int choice;
    input_property_field_enum("Type", options, 2, &choice);
    return (LandType)choice;
}

Temperature input_temperature(void) {
    const char *options[] = {"Cold", "Hot", "Medium"};
    int choice;
    input_property_field_enum("Temperature", options, 3, &choice);
    return (Temperature)choice;
}

YesNo input_yes_no(const char *prompt) {
    const char *options[] = {"Yes", "No"};
    int choice;
    input_property_field_enum(prompt, options, 2, &choice);
    return (YesNo)choice;
}

int input_property(Property *prop, const char *username) {
    char input[MAX_STRING_LEN];
    
    memset(prop, 0, sizeof(Property));
    
    printf("\n=== Enter Property Information ===\n\n");
    
    if (!input_property_field_string("Code", prop->code, MAX_FIELD_LEN, NULL)) return 0;
    
    if (!input_property_field_int("District", 1, 30, &prop->district)) return 0;
    
    if (!input_property_field_string("Address", prop->address, MAX_STRING_LEN, NULL)) return 0;
    
    prop->location = input_location();
    
    printf("\nProperty Category:\n");
    printf("1. Residential\n");
    printf("2. Commercial\n");
    printf("3. Land\n");
    int cat_choice;
    if (!input_property_field_int("Select category", 1, 3, &cat_choice)) return 0;
    prop->ptype = (PropertyType)(cat_choice - 1);
    
    printf("\nTransaction Type:\n");
    printf("1. Sell\n");
    printf("2. Rent\n");
    int action_choice;
    if (!input_property_field_int("Select action", 1, 2, &action_choice)) return 0;
    prop->action = (PropertyAction)(action_choice - 1);
    
    switch (prop->ptype) {
        case PROP_TYPE_RESIDENTIAL:
            prop->subtype.res_type = input_residential_type();
            break;
        case PROP_TYPE_COMMERCIAL:
            prop->subtype.com_type = input_commercial_type();
            break;
        case PROP_TYPE_LAND:
            prop->subtype.land_type = input_land_type();
            break;
    }
    
    if (prop->ptype != PROP_TYPE_LAND) {
        if (!input_property_field_int("Build Age (years)", 0, 200, &prop->build_age)) return 0;
        if (!input_property_field_double("Floor Area (m²)", 0, 100000, &prop->floor_area)) return 0;
        if (!input_property_field_int("Floor", 1, 50, &prop->floor)) return 0;
    }
    
    if (!input_property_field_double("Land Area (m²)", 0, 100000, &prop->land_area)) return 0;
    
    if (!input_property_field_string("Owner Phone Number", prop->owner_phone, MAX_FIELD_LEN, validate_phone)) return 0;
    
    if (prop->ptype == PROP_TYPE_RESIDENTIAL) {
        if (!input_property_field_int("Bedrooms", 0, 10, &prop->bedrooms)) return 0;
    } else if (prop->ptype == PROP_TYPE_COMMERCIAL) {
        if (!input_property_field_int("Rooms", 0, 10, &prop->rooms)) return 0;
    }
    
    if (prop->ptype == PROP_TYPE_LAND) {
        if (!input_property_field_double("Width (m)", 0, 10000, &prop->floor_area)) return 0;
    }
    
    if (!input_property_field_double("Tax Rate (%)", 0, 100, &prop->tax_rate)) return 0;
    
    if (prop->ptype != PROP_TYPE_LAND) {
        prop->elevator = input_yes_no("Elevator");
        prop->basement = input_yes_no("Basement");
        if (prop->basement == YES_NO_YES) {
            if (!input_property_field_double("Basement Area (m²)", 0, 10000, &prop->basement_area)) return 0;
        } else {
            prop->basement_area = 0;
        }
        prop->balcony = input_yes_no("Balcony");
        if (prop->balcony == YES_NO_YES) {
            if (!input_property_field_double("Balcony Area (m²)", 0, 1000, &prop->balcony_area)) return 0;
        } else {
            prop->balcony_area = 0;
        }
    } else {
        prop->elevator = YES_NO_NO;
        prop->basement = YES_NO_NO;
        prop->basement_area = 0;
        prop->balcony = YES_NO_NO;
        prop->balcony_area = 0;
    }
    
    if (!input_property_field_int("Parkings", 0, 10, &prop->parkings)) return 0;
    if (!input_property_field_int("Phones", 0, 10, &prop->phones)) return 0;
    
    prop->temperature = input_temperature();
    
    if (prop->action == PROP_ACTION_SELL) {
        if (!input_property_field_double("Sell Price (Rials)", 0, 1e12, &prop->sell_price)) return 0;
        prop->base_price = 0;
        prop->monthly_price = 0;
    } else {
        if (!input_property_field_double("Base Price (Rials)", 0, 1e12, &prop->base_price)) return 0;
        if (!input_property_field_double("Monthly Price (Rials)", 0, 1e12, &prop->monthly_price)) return 0;
        prop->sell_price = 0;
    }
    
    get_current_date(prop->date, MAX_FIELD_LEN);
    strncpy(prop->username, username, MAX_FIELD_LEN - 1);
    prop->username[MAX_FIELD_LEN - 1] = '\0';
    prop->active = true;
    
    return 1;
}

const char *location_to_string(Location loc) {
    static const char *names[] = {"North", "South", "East", "West"};
    return (loc >= 0 && loc < 4) ? names[loc] : "Unknown";
}

const char *residential_type_to_string(ResidentialType type) {
    static const char *names[] = {"Apartment", "Villa"};
    return (type >= 0 && type < 2) ? names[type] : "Unknown";
}

const char *commercial_type_to_string(CommercialType type) {
    static const char *names[] = {"Official", "Position"};
    return (type >= 0 && type < 2) ? names[type] : "Unknown";
}

const char *land_type_to_string(LandType type) {
    static const char *names[] = {"Farm", "City"};
    return (type >= 0 && type < 2) ? names[type] : "Unknown";
}

const char *temperature_to_string(Temperature temp) {
    static const char *names[] = {"Cold", "Hot", "Medium"};
    return (temp >= 0 && temp < 3) ? names[temp] : "Unknown";
}

const char *yes_no_to_string(YesNo yn) {
    static const char *names[] = {"No", "Yes"};
    return (yn >= 0 && yn < 2) ? names[yn] : "Unknown";
}

const char *property_type_to_string(PropertyType type) {
    static const char *names[] = {"Residential", "Commercial", "Land"};
    return (type >= 0 && type < 3) ? names[type] : "Unknown";
}

const char *property_action_to_string(PropertyAction action) {
    static const char *names[] = {"Sell", "Rent"};
    return (action >= 0 && action < 2) ? names[action] : "Unknown";
}