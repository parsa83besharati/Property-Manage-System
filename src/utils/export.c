#include "export.h"
#include "database.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void escape_csv(char *dest, const char *src, size_t dest_size) {
    size_t i = 0, j = 0;
    bool needs_quotes = false;
    
    while (src[i] && j < dest_size - 1) {
        if (src[i] == '"') {
            if (j + 1 < dest_size - 1) {
                dest[j++] = '"';
                dest[j++] = '"';
            }
            needs_quotes = true;
        } else if (src[i] == ',' || src[i] == '\n' || src[i] == '\r') {
            dest[j++] = src[i];
            needs_quotes = true;
        } else {
            dest[j++] = src[i];
        }
        i++;
    }
    dest[j] = '\0';
    
    if (needs_quotes && j + 2 < dest_size) {
        memmove(dest + 1, dest, j + 1);
        dest[0] = '"';
        dest[j + 1] = '"';
        dest[j + 2] = '\0';
    }
}

int export_users_to_csv(Database *db, const char *filename) {
    if (!db || !filename) return 0;
    
    User *users = NULL;
    int count = 0;
    if (!db_user_list_all(db, &users, &count)) return 0;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        free(users);
        return 0;
    }
    
    fprintf(fp, "username,first_name,last_name,id,phone,email,created_at\n");
    
    for (int i = 0; i < count; i++) {
        char esc_username[256], esc_first[256], esc_last[256];
        char esc_id[256], esc_phone[256], esc_email[256], esc_created[256];
        
        escape_csv(esc_username, users[i].username, sizeof(esc_username));
        escape_csv(esc_first, users[i].first_name, sizeof(esc_first));
        escape_csv(esc_last, users[i].last_name, sizeof(esc_last));
        escape_csv(esc_id, users[i].id, sizeof(esc_id));
        escape_csv(esc_phone, users[i].phone, sizeof(esc_phone));
        escape_csv(esc_email, users[i].email, sizeof(esc_email));
        escape_csv(esc_created, "", sizeof(esc_created));
        
        fprintf(fp, "%s,%s,%s,%s,%s,%s,%s\n",
                esc_username, esc_first, esc_last, esc_id, esc_phone, esc_email, esc_created);
    }
    
    fclose(fp);
    free(users);
    return 1;
}

int export_properties_to_csv(Database *db, const char *filename) {
    if (!db || !filename) return 0;
    
    Property *props = NULL;
    int count = 0;
    if (!db_property_list_all(db, &props, &count)) return 0;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        free(props);
        return 0;
    }
    
    fprintf(fp, "code,district,address,location,type,action,subtype,build_age,floor_area,floor,land_area,owner_phone,bedrooms,rooms,tax_rate,elevator,basement,basement_area,balcony,balcony_area,parkings,phones,temperature,sell_price,base_price,monthly_price,date,image_path,username,active\n");
    
    const char *ptype_str[] = {"Residential", "Commercial", "Land"};
    const char *action_str[] = {"Sell", "Rent"};
    const char *loc_str[] = {"North", "South", "East", "West"};
    const char *res_sub[] = {"Apartment", "Villa"};
    const char *com_sub[] = {"Official", "Position"};
    const char *land_sub[] = {"Farm", "City"};
    const char *temp_str[] = {"Cold", "Hot", "Medium"};
    const char *yn_str[] = {"No", "Yes"};
    
    for (int i = 0; i < count; i++) {
        Property *p = &props[i];
        char esc_code[64], esc_addr[512], esc_phone[64], esc_date[64], esc_user[64], esc_image[512];
        char esc_addr_escaped[512];
        
        escape_csv(esc_code, p->code, sizeof(esc_code));
        escape_csv(esc_addr_escaped, p->address, sizeof(esc_addr_escaped));
        escape_csv(esc_phone, p->owner_phone, sizeof(esc_phone));
        escape_csv(esc_date, p->date, sizeof(esc_date));
        escape_csv(esc_user, p->username, sizeof(esc_user));
        escape_csv(esc_image, p->image_path, sizeof(esc_image));
        
        const char *subtype = "";
        if (p->ptype == 0) subtype = res_sub[p->subtype.res_type];
        else if (p->ptype == 1) subtype = com_sub[p->subtype.com_type];
        else if (p->ptype == 2) subtype = land_sub[p->subtype.land_type];
        
        fprintf(fp, "%s,%d,%s,%s,%s,%s,%s,%d,%.2f,%d,%.2f,%s,%d,%d,%.2f,%d,%d,%.2f,%d,%.2f,%d,%d,%d,%.2f,%.2f,%.2f,%s,%s,%s,%d\n",
                esc_code, p->district, esc_addr_escaped, loc_str[p->location],
                ptype_str[p->ptype], action_str[p->action], subtype,
                p->build_age, p->floor_area, p->floor, p->land_area,
                esc_phone, p->bedrooms, p->rooms, p->tax_rate,
                p->elevator, p->basement, p->basement_area,
                p->balcony, p->balcony_area, p->parkings, p->phones,
                p->temperature, p->sell_price, p->base_price, p->monthly_price,
                esc_date, esc_image, esc_user, p->active);
    }
    
    fclose(fp);
    free(props);
    return 1;
}

// =============================================================================
// LEASE EXPORT FUNCTIONS
// =============================================================================

int export_leases_to_csv(Database *db, const char *filename) {
    if (!db || !filename) return 0;
    
    Lease *leases = NULL;
    int count = 0;
    if (!db_lease_list_all(db, &leases, &count)) return 0;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        free(leases);
        return 0;
    }
    
    fprintf(fp, "id,property_code,tenant_username,start_date,end_date,monthly_rent,deposit,payment_day,status,auto_renew,created_at\n");
    
    const char *status_str[] = {"Active", "Expired", "Terminated", "Pending"};
    const char *yn_str[] = {"No", "Yes"};
    
    for (int i = 0; i < count; i++) {
        Lease *l = &leases[i];
        char esc_prop[64], esc_tenant[64], esc_start[64], esc_end[64], esc_created[64];
        escape_csv(esc_prop, l->property_code, sizeof(esc_prop));
        escape_csv(esc_tenant, l->tenant_username, sizeof(esc_tenant));
        escape_csv(esc_start, l->start_date, sizeof(esc_start));
        escape_csv(esc_end, l->end_date, sizeof(esc_end));
        escape_csv(esc_created, l->created_at, sizeof(esc_created));
        
        fprintf(fp, "%d,%s,%s,%s,%s,%.2f,%.2f,%d,%s,%s,%s\n",
                l->id, esc_prop, esc_tenant, esc_start, esc_end,
                l->monthly_rent, l->deposit, l->payment_day,
                status_str[l->status], yn_str[l->auto_renew], esc_created);
    }
    
    fclose(fp);
    free(leases);
    return 1;
}

int export_payments_to_csv(Database *db, const char *filename) {
    if (!db || !filename) return 0;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) return 0;
    
    fprintf(fp, "id,lease_id,amount,payment_date,due_date,is_late,late_fee,notes,recorded_by,created_at\n");
    
    fclose(fp);
    return 1;
}

int export_all_to_csv(Database *db, const char *users_file, const char *properties_file, const char *leases_file, const char *payments_file) {
    if (!db || !users_file || !properties_file || !leases_file || !payments_file) return 0;
    if (!export_users_to_csv(db, users_file)) return 0;
    if (!export_properties_to_csv(db, properties_file)) return 0;
    if (!export_leases_to_csv(db, leases_file)) return 0;
    if (!export_payments_to_csv(db, payments_file)) return 0;
    return 1;
}

// =============================================================================
// CSV PARSING HELPERS
// =============================================================================

// Parse a single CSV line into fields, handling quoted fields
static int parse_csv_line(const char *line, char fields[][MAX_STRING_LEN], int max_fields) {
    int field_count = 0;
    const char *p = line;
    char *dest = fields[0];
    int in_quotes = 0;
    
    while (*p && field_count < max_fields) {
        if (*p == '"') {
            if (in_quotes && *(p + 1) == '"') {
                // Escaped quote
                *dest++ = '"';
                p += 2;
            } else {
                // Toggle quote state
                in_quotes = !in_quotes;
                p++;
            }
        } else if (*p == ',' && !in_quotes) {
            // End of field
            *dest = '\0';
            field_count++;
            if (field_count < max_fields) {
                dest = fields[field_count];
            }
            p++;
        } else if ((*p == '\n' || *p == '\r') && !in_quotes) {
            // End of line
            *dest = '\0';
            field_count++;
            break;
        } else {
            *dest++ = *p++;
        }
    }
    
    if (field_count < max_fields && dest != fields[field_count]) {
        *dest = '\0';
        field_count++;
    }
    
    return field_count;
}

// Trim whitespace from both ends of string
static void trim_string(char *str) {
    if (!str) return;
    
    // Trim leading whitespace
    char *start = str;
    while (*start && (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')) {
        start++;
    }
    
    // Trim trailing whitespace
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end-- = '\0';
    }
    
    // Move trimmed string to start
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

// Parse property type string to enum
static PropertyType parse_property_type(const char *str) {
    if (strcasecmp(str, "Residential") == 0) return PROP_TYPE_RESIDENTIAL;
    if (strcasecmp(str, "Commercial") == 0) return PROP_TYPE_COMMERCIAL;
    if (strcasecmp(str, "Land") == 0) return PROP_TYPE_LAND;
    return PROP_TYPE_RESIDENTIAL; // default
}

// Parse action string to enum
static PropertyAction parse_action(const char *str) {
    if (strcasecmp(str, "Sell") == 0) return PROP_ACTION_SELL;
    if (strcasecmp(str, "Rent") == 0) return PROP_ACTION_RENT;
    return PROP_ACTION_SELL; // default
}

// Parse location string to enum
static Location parse_location(const char *str) {
    if (strcasecmp(str, "North") == 0) return LOCATION_NORTH;
    if (strcasecmp(str, "South") == 0) return LOCATION_SOUTH;
    if (strcasecmp(str, "East") == 0) return LOCATION_EAST;
    if (strcasecmp(str, "West") == 0) return LOCATION_WEST;
    return LOCATION_NORTH; // default
}

// Parse subtype string based on property type
static void parse_subtype(Property *prop, const char *str) {
    if (prop->ptype == PROP_TYPE_RESIDENTIAL) {
        if (strcasecmp(str, "Apartment") == 0) prop->subtype.res_type = RES_TYPE_APARTMENT;
        else if (strcasecmp(str, "Villa") == 0) prop->subtype.res_type = RES_TYPE_VILLA;
        else prop->subtype.res_type = RES_TYPE_APARTMENT;
    } else if (prop->ptype == PROP_TYPE_COMMERCIAL) {
        if (strcasecmp(str, "Official") == 0) prop->subtype.com_type = COM_TYPE_OFFICIAL;
        else if (strcasecmp(str, "Position") == 0) prop->subtype.com_type = COM_TYPE_POSITION;
        else prop->subtype.com_type = COM_TYPE_OFFICIAL;
    } else if (prop->ptype == PROP_TYPE_LAND) {
        if (strcasecmp(str, "Farm") == 0) prop->subtype.land_type = LAND_TYPE_FARM;
        else if (strcasecmp(str, "City") == 0) prop->subtype.land_type = LAND_TYPE_CITY;
        else prop->subtype.land_type = LAND_TYPE_FARM;
    }
}

// Parse Yes/No to int
static int parse_yes_no(const char *str) {
    if (strcasecmp(str, "Yes") == 0) return 1;
    if (strcasecmp(str, "No") == 0) return 0;
    return atoi(str); // fallback to numeric
}

// Parse temperature string to enum
static Temperature parse_temperature(const char *str) {
    if (strcasecmp(str, "Cold") == 0) return TEMP_COLD;
    if (strcasecmp(str, "Hot") == 0) return TEMP_HOT;
    if (strcasecmp(str, "Medium") == 0) return TEMP_MEDIUM;
    return TEMP_MEDIUM;
}

// =============================================================================
// CSV IMPORT FUNCTIONS
// =============================================================================

int import_users_from_csv(Database *db, const char *filename, int *imported, int *skipped) {
    if (!db || !filename) return 0;
    
    FILE *fp = fopen(filename, "r");
    if (!fp) return 0;
    
    if (imported) *imported = 0;
    if (skipped) *skipped = 0;
    
    char line[4096];
    char fields[8][MAX_STRING_LEN];
    int line_num = 0;
    int first_line = 1;
    
    // Generate salt for new users
    char salt[SALT_LENGTH + 1];
    // We'll use a simple default password hash for imported users
    const char *default_hash = "imported_password_hash_placeholder";
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        
        // Skip header line
        if (first_line) {
            first_line = 0;
            continue;
        }
        
        // Skip empty lines
        if (strlen(line) < 3) continue;
        
        int field_count = parse_csv_line(line, fields, 8);
        if (field_count < 6) {
            if (skipped) (*skipped)++;
            continue;
        }
        
        trim_string(fields[0]); // username
        trim_string(fields[1]); // first_name
        trim_string(fields[2]); // last_name
        trim_string(fields[3]); // id
        trim_string(fields[4]); // phone
        trim_string(fields[5]); // email
        
        // Check if user already exists
        if (db_user_find_by_username(db, fields[0])) {
            if (skipped) (*skipped)++;
            continue;
        }
        
        // Create user
        User user;
        memset(&user, 0, sizeof(User));
        strncpy(user.username, fields[0], MAX_FIELD_LEN - 1);
        strncpy(user.first_name, fields[1], MAX_FIELD_LEN - 1);
        strncpy(user.last_name, fields[2], MAX_FIELD_LEN - 1);
        strncpy(user.id, fields[3], MAX_FIELD_LEN - 1);
        strncpy(user.phone, fields[4], MAX_FIELD_LEN - 1);
        strncpy(user.email, fields[5], MAX_FIELD_LEN - 1);
        strncpy(user.password_hash, default_hash, SHA256_DIGEST_LENGTH * 2);
        strncpy(user.salt, "imported_salt_1234", SALT_LENGTH);
        user.role = ROLE_USER;
        
        if (db_user_create(db, &user)) {
            if (imported) (*imported)++;
        } else {
            if (skipped) (*skipped)++;
        }
    }
    
    fclose(fp);
    return 1;
}

int import_properties_from_csv(Database *db, const char *filename, int *imported, int *skipped) {
    if (!db || !filename) return 0;
    
    FILE *fp = fopen(filename, "r");
    if (!fp) return 0;
    
    if (imported) *imported = 0;
    if (skipped) *skipped = 0;
    
    char line[8192];
    char fields[30][MAX_STRING_LEN];
    int first_line = 1;
    
    while (fgets(line, sizeof(line), fp)) {
        // Skip header line
        if (first_line) {
            first_line = 0;
            continue;
        }
        
        // Skip empty lines
        if (strlen(line) < 3) continue;
        
        int field_count = parse_csv_line(line, fields, 30);
        if (field_count < 29) {
            if (skipped) (*skipped)++;
            continue;
        }
        
        // Trim all fields
        for (int i = 0; i < field_count; i++) {
            trim_string(fields[i]);
        }
        
        // Fields: code,district,address,location,type,action,subtype,build_age,floor_area,floor,
        // land_area,owner_phone,bedrooms,rooms,tax_rate,elevator,basement,basement_area,
        // balcony,balcony_area,parkings,phones,temperature,sell_price,base_price,monthly_price,
        // date,image_path,username,active
        
        const char *code = fields[0];
        if (!code || strlen(code) == 0) {
            if (skipped) (*skipped)++;
            continue;
        }
        
        // Check if property already exists
        if (db_property_find_by_code(db, code)) {
            if (skipped) (*skipped)++;
            continue;
        }
        
        // Check if user exists
        const char *username = fields[28];
        if (!username || strlen(username) == 0) {
            if (skipped) (*skipped)++;
            continue;
        }
        
        if (!db_user_find_by_username(db, username)) {
            if (skipped) (*skipped)++;
            continue;
        }
        
        // Create property
        Property prop;
        memset(&prop, 0, sizeof(Property));
        
        strncpy(prop.code, code, MAX_FIELD_LEN - 1);
        prop.district = atoi(fields[1]);
        strncpy(prop.address, fields[2], MAX_STRING_LEN - 1);
        prop.location = parse_location(fields[3]);
        prop.ptype = parse_property_type(fields[4]);
        prop.action = parse_action(fields[5]);
        parse_subtype(&prop, fields[6]);
        prop.build_age = atoi(fields[7]);
        prop.floor_area = atof(fields[8]);
        prop.floor = atoi(fields[9]);
        prop.land_area = atof(fields[10]);
        strncpy(prop.owner_phone, fields[11], MAX_FIELD_LEN - 1);
        prop.bedrooms = atoi(fields[12]);
        prop.rooms = atoi(fields[13]);
        prop.tax_rate = atof(fields[14]);
        prop.elevator = parse_yes_no(fields[15]);
        prop.basement = parse_yes_no(fields[16]);
        prop.basement_area = atof(fields[17]);
        prop.balcony = parse_yes_no(fields[18]);
        prop.balcony_area = atof(fields[19]);
        prop.parkings = atoi(fields[20]);
        prop.phones = atoi(fields[21]);
        prop.temperature = parse_temperature(fields[22]);
        prop.sell_price = atof(fields[23]);
        prop.base_price = atof(fields[24]);
        prop.monthly_price = atof(fields[25]);
        strncpy(prop.date, fields[26], MAX_FIELD_LEN - 1);
        strncpy(prop.image_path, fields[27], MAX_STRING_LEN - 1);
        strncpy(prop.username, username, MAX_FIELD_LEN - 1);
        prop.active = atoi(fields[29]);
        
        if (db_property_create(db, &prop)) {
            if (imported) (*imported)++;
        } else {
            if (skipped) (*skipped)++;
        }
    }
    
    fclose(fp);
    return 1;
}