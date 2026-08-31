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
    
    fprintf(fp, "code,district,address,location,type,action,subtype,build_age,floor_area,floor,land_area,owner_phone,bedrooms,rooms,tax_rate,elevator,basement,basement_area,balcony,balcony_area,parkings,phones,temperature,sell_price,base_price,monthly_price,date,username,active\n");
    
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
        char esc_code[64], esc_addr[512], esc_phone[64], esc_date[64], esc_user[64];
        char esc_addr_escaped[512];
        
        escape_csv(esc_code, p->code, sizeof(esc_code));
        escape_csv(esc_addr_escaped, p->address, sizeof(esc_addr_escaped));
        escape_csv(esc_phone, p->owner_phone, sizeof(esc_phone));
        escape_csv(esc_date, p->date, sizeof(esc_date));
        escape_csv(esc_user, p->username, sizeof(esc_user));
        
        const char *subtype = "";
        if (p->ptype == 0) subtype = res_sub[p->subtype.res_type];
        else if (p->ptype == 1) subtype = com_sub[p->subtype.com_type];
        else if (p->ptype == 2) subtype = land_sub[p->subtype.land_type];
        
        fprintf(fp, "%s,%d,%s,%s,%s,%s,%s,%d,%.2f,%d,%.2f,%s,%d,%d,%.2f,%d,%d,%.2f,%d,%.2f,%d,%d,%d,%.2f,%.2f,%.2f,%s,%s,%d\n",
                esc_code, p->district, esc_addr_escaped, loc_str[p->location],
                ptype_str[p->ptype], action_str[p->action], subtype,
                p->build_age, p->floor_area, p->floor, p->land_area,
                esc_phone, p->bedrooms, p->rooms, p->tax_rate,
                p->elevator, p->basement, p->basement_area,
                p->balcony, p->balcony_area, p->parkings, p->phones,
                p->temperature, p->sell_price, p->base_price, p->monthly_price,
                esc_date, esc_user, p->active);
    }
    
    fclose(fp);
    free(props);
    return 1;
}

int export_all_to_csv(Database *db, const char *users_file, const char *properties_file) {
    if (!db || !users_file || !properties_file) return 0;
    if (!export_users_to_csv(db, users_file)) return 0;
    if (!export_properties_to_csv(db, properties_file)) return 0;
    return 1;
}