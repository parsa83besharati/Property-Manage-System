#include "menu.h"
#include <stdio.h>
#include <stdlib.h>

void menu_entry(UserManager *um, PropertyManager *pm) {
    int choice;
    char logged_in_username[MAX_FIELD_LEN];
    
    while (1) {
        clear_screen();
        print_header("PROPERTY MANAGEMENT SYSTEM");
        printf("1. Login\n");
        printf("2. Sign Up\n");
        printf("3. Exit\n");
        
        if (!input_property_field_int("Enter your choice", 1, 3, &choice)) continue;
        
        switch (choice) {
            case 1: {
                int result = user_login(um, logged_in_username);
                if (result == 1) {
                    menu_main(um, pm, logged_in_username);
                } else if (result == 2) {
                    menu_admin(um, pm);
                }
                break;
            }
            case 2:
                user_register(um);
                break;
            case 3:
                printf("Goodbye!\n");
                return;
        }
    }
}

void menu_main(UserManager *um, PropertyManager *pm, const char *username) {
    int choice;
    
    while (1) {
        clear_screen();
        print_header("MAIN MENU");
        printf("Logged in as: %s\n\n", username);
        printf("1. Add Property\n");
        printf("2. Delete Property\n");
        printf("3. Reports\n");
        printf("4. User Settings\n");
        printf("5. Logout\n");
        
        if (!input_property_field_int("Enter your choice", 1, 5, &choice)) continue;
        
        switch (choice) {
            case 1:
                menu_add_property(um, pm, username);
                break;
            case 2:
                menu_delete_property(pm, username);
                break;
            case 3:
                menu_reports(pm);
                break;
            case 4:
                menu_user_settings(um, username);
                break;
            case 5:
                return;
        }
    }
}

void menu_add_property(UserManager *um, PropertyManager *pm, const char *username) {
    clear_screen();
    print_header("ADD PROPERTY");
    
    Property prop;
    if (input_property(&prop, username)) {
        if (property_manager_add(pm, &prop)) {
            printf("\nProperty added successfully!\n");
            printf("Code: %s\n", prop.code);
        } else {
            printf("\nFailed to add property. Code may already exist.\n");
        }
    } else {
        printf("\nProperty entry cancelled.\n");
    }
    pause_screen();
}

void menu_delete_property(PropertyManager *pm, const char *username) {
    clear_screen();
    print_header("DELETE PROPERTY");
    
    char code[MAX_FIELD_LEN];
    if (!input_property_field_string("Enter property code to delete", code, MAX_FIELD_LEN, NULL)) {
        pause_screen();
        return;
    }
    
    Property *prop = property_manager_find(pm, code);
    if (!prop) {
        printf("Property not found.\n");
        pause_screen();
        return;
    }
    
    if (strcmp(prop->username, username) != 0 && strcmp(username, "Admin") != 0) {
        printf("You can only delete your own properties.\n");
        pause_screen();
        return;
    }
    
    property_print(prop);
    printf("\nAre you sure you want to delete this property? ");
    if (input_yes_no("Confirm") == YES_NO_YES) {
        if (property_manager_delete(pm, code)) {
            printf("Property deleted successfully.\n");
        } else {
            printf("Failed to delete property.\n");
        }
    } else {
        printf("Deletion cancelled.\n");
    }
    pause_screen();
}

void menu_reports(PropertyManager *pm) {
    int choice;
    
    while (1) {
        clear_screen();
        print_header("REPORTS");
        printf("1. All Properties\n");
        printf("2. Sell - Residential\n");
        printf("3. Sell - Commercial\n");
        printf("4. Sell - Land\n");
        printf("5. Rent - Residential\n");
        printf("6. Rent - Commercial\n");
        printf("7. Rent - Land\n");
        printf("8. By District\n");
        printf("9. By Location\n");
        printf("10. By Price Range\n");
        printf("11. Property Counters\n");
        printf("0. Back\n");
        
        if (!input_property_field_int("Enter your choice", 0, 11, &choice)) continue;
        
        if (choice == 0) break;
        
        clear_screen();
        print_header("REPORT RESULTS");
        
        switch (choice) {
            case 1:
                property_manager_list_all(pm);
                break;
            case 2:
                property_manager_list_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL);
                break;
            case 3:
                property_manager_list_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_SELL);
                break;
            case 4:
                property_manager_list_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_SELL);
                break;
            case 5:
                property_manager_list_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_RENT);
                break;
            case 6:
                property_manager_list_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_RENT);
                break;
            case 7:
                property_manager_list_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_RENT);
                break;
            case 8: {
                int district;
                if (input_property_field_int("Enter district", 1, 30, &district)) {
                    property_manager_list_by_district(pm, district);
                }
                break;
            }
            case 9: {
                Location loc = input_location();
                property_manager_list_by_location(pm, loc);
                break;
            }
            case 10: {
                double min, max;
                if (input_property_field_double("Min price", 0, 1e12, &min) &&
                    input_property_field_double("Max price", min, 1e12, &max)) {
                    property_manager_list_by_price_range(pm, min, max);
                }
                break;
            }
            case 11:
                printf("Sell Residential: %d\n", property_count_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL));
                printf("Sell Commercial: %d\n", property_count_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_SELL));
                printf("Sell Land: %d\n", property_count_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_SELL));
                printf("Rent Residential: %d\n", property_count_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_RENT));
                printf("Rent Commercial: %d\n", property_count_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_RENT));
                printf("Rent Land: %d\n", property_count_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_RENT));
                break;
        }
        pause_screen();
    }
}

void menu_user_settings(UserManager *um, const char *username) {
    user_edit_profile(um, username);
}

void menu_admin(UserManager *um, PropertyManager *pm) {
    int choice;
    
    while (1) {
        clear_screen();
        print_header("ADMIN MENU");
        printf("1. View All Users\n");
        printf("2. View All Properties (including inactive)\n");
        printf("3. Delete Any Property\n");
        printf("4. System Statistics\n");
        printf("0. Back\n");
        
        if (!input_property_field_int("Enter your choice", 0, 4, &choice)) continue;
        
        if (choice == 0) break;
        
        clear_screen();
        print_header("ADMIN RESULTS");
        
        switch (choice) {
            case 1:
                user_manager_list_all(um);
                break;
            case 2:
                for (int i = 0; i < pm->count; i++) {
                    property_print_short(&pm->properties[i]);
                }
                break;
            case 3: {
                char code[MAX_FIELD_LEN];
                if (input_property_field_string("Enter property code to delete", code, MAX_FIELD_LEN, NULL)) {
                    if (property_manager_delete(pm, code)) {
                        printf("Property deleted.\n");
                    } else {
                        printf("Property not found.\n");
                    }
                }
                break;
            }
            case 4:
                printf("Total Users: %d\n", um->count);
                printf("Total Properties: %d\n", pm->count);
                printf("Active Properties: %d\n", property_count_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL) +
                    property_count_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_SELL) +
                    property_count_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_SELL) +
                    property_count_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_RENT) +
                    property_count_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_RENT) +
                    property_count_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_RENT));
                break;
        }
        pause_screen();
    }
}