#include "menu.h"
#include "ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <conio.h>

void menu_entry(UserManager *um, PropertyManager *pm) {
    ui_init();
    
    char logged_in_username[MAX_FIELD_LEN];
    const char *entry_options[] = {"Login to your account", "Create new account", "Exit application"};
    
    while (1) {
        ui_clear();
        ui_header("PROPERTY MANAGEMENT SYSTEM", "Modern Terminal Interface v2.0");
        
        ui_menu_start("MAIN MENU");
        for (int i = 0; i < 3; i++) {
            ui_menu_item(i + 1, 
                i == 0 ? "Login" : (i == 1 ? "Sign Up" : "Exit"),
                entry_options[i], false);
        }
        
        int choice = ui_menu_end("Select option", 1, 3);
        
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
                ui_alert(UI_STYLE_INFO, "Goodbye", "Thank you for using Property Management System!");
                return;
            default:
                ui_toast(UI_STYLE_ERROR, "Invalid option. Please try again.");
                Sleep(1000);
        }
    }
}

void menu_main(UserManager *um, PropertyManager *pm, const char *username) {
    const char *main_options[] = {
        "Add new property listing",
        "Remove your property listing",
        "View reports and analytics",
        "Manage your profile",
        "Sign out"
    };
    
    while (1) {
        char time_str[20];
        get_current_time(time_str, sizeof(time_str));
        ui_clear();
        ui_header("MAIN MENU", "Property Management Dashboard");
        ui_status_bar(username, "USER", time_str);
        
        ui_menu_start("MAIN MENU");
        for (int i = 0; i < 5; i++) {
            ui_menu_item(i + 1, 
                i == 0 ? "Add Property" : 
                i == 1 ? "Delete Property" :
                i == 2 ? "Reports" :
                i == 3 ? "Settings" : "Logout",
                main_options[i], false);
        }
        
        int choice = ui_menu_end("Select option", 1, 5);
        
        switch (choice) {
            case 1: menu_add_property(um, pm, username); break;
            case 2: menu_delete_property(pm, username); break;
            case 3: menu_reports(pm); break;
            case 4: menu_user_settings(um, username); break;
            case 5: return;
            default: ui_toast(UI_STYLE_ERROR, "Invalid option"); Sleep(1000);
        }
    }
}

void menu_add_property(UserManager *um, PropertyManager *pm, const char *username) {
    ui_clear();
    ui_header("ADD PROPERTY", "Create a new property listing");
    
    Property prop;
    if (input_property(&prop, username)) {
        ui_spinner_start("Saving property...");
        Sleep(500);
        bool success = property_manager_add(pm, &prop);
        ui_spinner_stop();
        
        if (success) {
            ui_alert(UI_STYLE_SUCCESS, "Success", "Property added successfully!");
            ui_print_styled(UI_STYLE_INFO, "  Property Code: %s\n", prop.code);
            ui_print_styled(UI_STYLE_INFO, "  Type: %s %s\n", 
                property_action_to_string(prop.action),
                property_type_to_string(prop.ptype));
            ui_print_styled(UI_STYLE_INFO, "  Price: %.2f %s\n",
                prop.action == PROP_ACTION_SELL ? prop.sell_price : prop.monthly_price,
                prop.action == PROP_ACTION_SELL ? "Rials (Sale)" : "Rials/Month");
        } else {
            ui_alert(UI_STYLE_ERROR, "Error", "Failed to add property. Code may already exist.");
        }
    } else {
        ui_toast(UI_STYLE_WARNING, "Property entry cancelled");
    }
    ui_spacer(1);
    ui_footer("Press any key to continue", "");
    _getch();
}

void menu_delete_property(PropertyManager *pm, const char *username) {
    ui_clear();
    ui_header("DELETE PROPERTY", "Remove a property listing");
    
    char code[MAX_FIELD_LEN];
    ui_form_start("DELETE PROPERTY");
    if (!ui_form_field("Property Code", code, MAX_FIELD_LEN, NULL, "Enter the code of the property to delete")) {
        return;
    }
    ui_form_end();
    
    Property *prop = property_manager_find(pm, code);
    if (!prop) {
        ui_alert(UI_STYLE_ERROR, "Not Found", "Property not found.");
        ui_footer("Press any key to continue", "");
        _getch();
        return;
    }
    
    if (strcmp(prop->username, username) != 0 && strcmp(username, "Admin") != 0) {
        ui_alert(UI_STYLE_ERROR, "Permission Denied", "You can only delete your own properties.");
        ui_footer("Press any key to continue", "");
        _getch();
        return;
    }
    
    ui_clear();
    ui_header("CONFIRM DELETION", "Review property details before deleting");
    property_print(prop);
    
    bool confirm = false;
    ui_confirm("This action cannot be undone. Delete this property?", &confirm);
    
    if (confirm) {
        ui_spinner_start("Deleting property...");
        Sleep(500);
        bool success = property_manager_delete(pm, code);
        ui_spinner_stop();
        
        if (success) {
            ui_alert(UI_STYLE_SUCCESS, "Deleted", "Property deleted successfully.");
        } else {
            ui_alert(UI_STYLE_ERROR, "Error", "Failed to delete property.");
        }
    } else {
        ui_toast(UI_STYLE_INFO, "Deletion cancelled");
    }
    ui_footer("Press any key to continue", "");
    _getch();
}

void menu_reports(PropertyManager *pm) {
    const char *report_options[] = {
        "All active properties",
        "Residential properties for sale",
        "Commercial properties for sale",
        "Land properties for sale",
        "Residential properties for rent",
        "Commercial properties for rent",
        "Land properties for rent",
        "Filter by district (1-30)",
        "Filter by location (N/S/E/W)",
        "Filter by price range",
        "Property statistics"
    };
    
    while (1) {
        char time_str[20];
        get_current_time(time_str, sizeof(time_str));
        ui_clear();
        ui_header("REPORTS & ANALYTICS", "View and filter property listings");
        ui_status_bar("User", "REPORTS", time_str);
        
        ui_menu_start("REPORTS");
        for (int i = 0; i < 11; i++) {
            const char *label = i == 0 ? "All Properties" :
                               i == 1 ? "Sell - Residential" :
                               i == 2 ? "Sell - Commercial" :
                               i == 3 ? "Sell - Land" :
                               i == 4 ? "Rent - Residential" :
                               i == 5 ? "Rent - Commercial" :
                               i == 6 ? "Rent - Land" :
                               i == 7 ? "By District" :
                               i == 8 ? "By Location" :
                               i == 9 ? "By Price Range" : "Statistics";
            ui_menu_item(i + 1, label, report_options[i], false);
        }
        ui_print_styled(UI_STYLE_MUTED, "   0. Back to Main Menu\n");
        
        int choice = ui_menu_end("Select report", 0, 11);
        
        if (choice == 0) break;
        
        ui_clear();
        ui_header("REPORT RESULTS", report_options[choice - 1]);
        
        switch (choice) {
            case 1: property_manager_list_all(pm); break;
            case 2: property_manager_list_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL); break;
            case 3: property_manager_list_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_SELL); break;
            case 4: property_manager_list_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_SELL); break;
            case 5: property_manager_list_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_RENT); break;
            case 6: property_manager_list_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_RENT); break;
            case 7: property_manager_list_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_RENT); break;
            case 8: {
                int district;
                if (ui_form_field_int("District", &district, 1, 30, "1-30")) {
                    property_manager_list_by_district(pm, district);
                }
                break;
            }
            case 9: {
                const char *locations[] = {"North", "South", "East", "West"};
                int loc_idx;
                if (ui_form_field_enum("Location", locations, 4, &loc_idx, "Select location")) {
                    property_manager_list_by_location(pm, (Location)loc_idx);
                }
                break;
            }
            case 10: {
                double min, max;
                if (ui_form_field_double("Min Price", &min, 0, 1e12, "Minimum price") &&
                    ui_form_field_double("Max Price", &max, min, 1e12, "Maximum price")) {
                    property_manager_list_by_price_range(pm, min, max);
                }
                break;
            }
            case 11: {
                const char *headers[] = {"Category", "Count"};
                int widths[] = {35, 10};
                ui_table_start(headers, 2, widths);
                
                char cells[2][64];
                snprintf(cells[0], 64, "%d", property_count_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL));
                snprintf(cells[1], 64, "%d", property_count_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_SELL));
                ui_table_row((const char*[]){"Sell - Residential", cells[0]}, 2);
                ui_table_row((const char*[]){"Sell - Commercial", cells[1]}, 2);
                
                snprintf(cells[0], 64, "%d", property_count_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_SELL));
                snprintf(cells[1], 64, "%d", property_count_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_RENT));
                ui_table_row((const char*[]){"Sell - Land", cells[0]}, 2);
                ui_table_row((const char*[]){"Rent - Residential", cells[1]}, 2);
                
                snprintf(cells[0], 64, "%d", property_count_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_RENT));
                snprintf(cells[1], 64, "%d", property_count_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_RENT));
                ui_table_row((const char*[]){"Rent - Commercial", cells[0]}, 2);
                ui_table_row((const char*[]){"Rent - Land", cells[1]}, 2);
                
                int total = property_count_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL) +
                           property_count_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_SELL) +
                           property_count_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_SELL) +
                           property_count_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_RENT) +
                           property_count_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_RENT) +
                           property_count_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_RENT);
                snprintf(cells[0], 64, "%d", total);
                ui_table_row((const char*[]){"TOTAL ACTIVE", cells[0]}, 2);
                
                ui_table_end();
                break;
            }
        }
        ui_footer("Press any key to continue", "");
        _getch();
    }
}

void menu_user_settings(UserManager *um, const char *username) {
    user_edit_profile(um, username);
}

void menu_admin(UserManager *um, PropertyManager *pm) {
    const char *admin_options[] = {
        "List all registered users",
        "View all properties (incl. inactive)",
        "Force delete any property",
        "System statistics overview"
    };
    
    while (1) {
        char time_str[20];
        get_current_time(time_str, sizeof(time_str));
        ui_clear();
        ui_header("ADMIN PANEL", "System Administration");
        ui_status_bar("Admin", "ADMIN", time_str);
        
        ui_menu_start("ADMIN MENU");
        for (int i = 0; i < 4; i++) {
            ui_menu_item(i + 1, 
                i == 0 ? "View Users" :
                i == 1 ? "All Properties" :
                i == 2 ? "Delete Property" : "Statistics",
                admin_options[i], false);
        }
        ui_print_styled(UI_STYLE_MUTED, "   0. Back\n");
        
        int choice = ui_menu_end("Select option", 0, 4);
        
        if (choice == 0) break;
        
        ui_clear();
        ui_header("ADMIN RESULTS", admin_options[choice - 1]);
        
        switch (choice) {
            case 1: {
                ui_print_styled(UI_STYLE_PRIMARY, "  %-20s %-20s %-15s %-25s\n", "Username", "Name", "Phone", "Email");
                ui_divider();
                for (int i = 0; i < um->count; i++) {
                    printf("  %-20s %-20s %-15s %-25s\n",
                        um->users[i].username,
                        um->users[i].first_name,
                        um->users[i].phone,
                        um->users[i].email);
                }
                break;
            }
            case 2: {
                for (int i = 0; i < pm->count; i++) {
                    property_print_short(&pm->properties[i]);
                }
                break;
            }
            case 3: {
                char code[MAX_FIELD_LEN];
                if (ui_form_field("Property Code", code, MAX_FIELD_LEN, NULL, "Enter code to force delete")) {
                    if (property_manager_delete(pm, code)) {
                        ui_alert(UI_STYLE_SUCCESS, "Deleted", "Property deleted successfully.");
                    } else {
                        ui_alert(UI_STYLE_ERROR, "Error", "Property not found.");
                    }
                }
                break;
            }
            case 4: {
                ui_print_styled(UI_STYLE_PRIMARY, "  System Statistics\n\n");
                ui_print_styled(UI_STYLE_INFO, "  Total Users: %d\n", um->count);
                ui_print_styled(UI_STYLE_INFO, "  Total Properties: %d\n", pm->count);
                
                int active = property_count_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL) +
                            property_count_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_SELL) +
                            property_count_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_SELL) +
                            property_count_by_type(pm, PROP_TYPE_RESIDENTIAL, PROP_ACTION_RENT) +
                            property_count_by_type(pm, PROP_TYPE_COMMERCIAL, PROP_ACTION_RENT) +
                            property_count_by_type(pm, PROP_TYPE_LAND, PROP_ACTION_RENT);
                ui_print_styled(UI_STYLE_SUCCESS, "  Active Properties: %d\n", active);
                ui_print_styled(UI_STYLE_WARNING, "  Inactive Properties: %d\n", pm->count - active);
                break;
            }
        }
        ui_footer("Press any key to continue", "");
        _getch();
    }
}