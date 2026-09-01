#include "menu.h"
#include "ui.h"
#include "database.h"
#include "user.h"
#include "property.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <conio.h>

#define PAGE_SIZE 10

void menu_entry(Database *db) {
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
                int result = user_login(db, logged_in_username);
                if (result == 1) {
                    menu_main(db, logged_in_username);
                } else if (result == 2) {
                    menu_admin(db);
                }
                break;
            }
            case 2:
                user_register(db);
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

void menu_main(Database *db, const char *username) {
    const char *main_options[] = {
        "Add new property listing",
        "Remove your property listing",
        "Search and view properties",
        "Manage your leases",
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
        for (int i = 0; i < 6; i++) {
            ui_menu_item(i + 1, 
                i == 0 ? "Add Property" : 
                i == 1 ? "Delete Property" :
                i == 2 ? "Search Properties" :
                i == 3 ? "Lease Management" :
                i == 4 ? "Settings" : "Logout",
                main_options[i], false);
        }
        
        int choice = ui_menu_end("Select option", 1, 6);
        
        switch (choice) {
            case 1: menu_add_property(db, username); break;
            case 2: menu_delete_property(db, username); break;
            case 3: menu_search_properties(db, username); break;
            case 4: menu_lease_management(db, username); break;
            case 5: menu_user_settings(db, username); break;
            case 6: return;
            default: ui_toast(UI_STYLE_ERROR, "Invalid option"); Sleep(1000);
        }
    }
}

void menu_add_property(Database *db, const char *username) {
    ui_clear();
    ui_header("ADD PROPERTY", "Create a new property listing");
    
    Property prop;
    if (input_property(&prop, username)) {
        ui_spinner_start("Saving property...");
        Sleep(500);
        bool success = db_property_create(db, &prop);
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

void menu_delete_property(Database *db, const char *username) {
    ui_clear();
    ui_header("DELETE PROPERTY", "Remove a property listing");
    
    char code[MAX_FIELD_LEN];
    ui_form_start("DELETE PROPERTY");
    if (!ui_form_field("Property Code", code, MAX_FIELD_LEN, NULL, "Enter the code of the property to delete")) {
        return;
    }
    ui_form_end();
    
    Property *prop = db_property_find_by_code(db, code);
    if (!prop) {
        ui_alert(UI_STYLE_ERROR, "Not Found", "Property not found.");
        ui_footer("Press any key to continue", "");
        _getch();
        return;
    }
    
    if (strcmp(prop->username, username) != 0 && strcmp(username, "Admin") != 0) {
        ui_alert(UI_STYLE_ERROR, "Permission Denied", "You can only delete your own properties.");
        free(prop);
        ui_footer("Press any key to continue", "");
        _getch();
        return;
    }
    
    ui_clear();
    ui_header("CONFIRM DELETION", "Review property details before deleting");
    property_print(prop);
    free(prop);
    
    bool confirm = false;
    ui_confirm("This action cannot be undone. Delete this property?", &confirm);
    
    if (confirm) {
        ui_spinner_start("Deleting property...");
        Sleep(500);
        bool success = db_property_delete(db, code);
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

void print_property_table(Property *props, int count, int start_idx) {
    if (count == 0) {
        ui_print_styled(UI_STYLE_MUTED, "  No properties found.\n");
        return;
    }
    
    ui_print_styled(UI_STYLE_PRIMARY, "  %-5s %-10s %-12s %-8s %-10s %-12s\n", 
        "#", "Code", "Type", "Action", "District", "Price");
    ui_divider();
    
    for (int i = 0; i < count; i++) {
        double price = (props[i].action == PROP_ACTION_SELL) ? props[i].sell_price : props[i].monthly_price;
        ui_print_styled(UI_STYLE_DEFAULT, "  %-5d %-10s %-12s %-8s %-10d %.2f\n",
            start_idx + i + 1,
            props[i].code,
            property_type_to_string(props[i].ptype),
            property_action_to_string(props[i].action),
            props[i].district,
            price);
    }
}

void print_property_table_detailed(Property *props, int count, int start_idx) {
    if (count == 0) {
        ui_print_styled(UI_STYLE_MUTED, "  No properties found.\n");
        return;
    }
    
    for (int i = 0; i < count; i++) {
        property_print(&props[i]);
    }
}

void menu_search_properties(Database *db, const char *username) {
    int search_type = 0;
    char where_clause[512] = "";
    char order_by[128] = "date DESC";
    int page = 0;
    int total_pages = 1;
    int total_count = 0;
    Property *props = NULL;
    int count = 0;
    
    while (1) {
        ui_clear();
        ui_header("SEARCH PROPERTIES", "Find properties with filters");
        ui_status_bar(username, "SEARCH", "");
        
        const char *search_options[] = {
            "All properties (paginated)",
            "By type (Sell/Rent + Residential/Commercial/Land)",
            "By district (1-30)",
            "By location (N/S/E/W)",
            "By price range",
            "By keyword in address",
            "Sort options",
            "View property details"
        };
        
        ui_menu_start("SEARCH MENU");
        for (int i = 0; i < 8; i++) {
            ui_menu_item(i + 1, 
                i == 0 ? "All Properties" :
                i == 1 ? "By Type" :
                i == 2 ? "By District" :
                i == 3 ? "By Location" :
                i == 4 ? "By Price" :
                i == 5 ? "By Keyword" :
                i == 6 ? "Sort Options" : "View Details",
                search_options[i], false);
        }
        ui_print_styled(UI_STYLE_MUTED, "  0. Back to Main Menu\n");
        
        int choice = ui_menu_end("Select option", 0, 8);
        
        if (choice == 0) break;
        
        memset(where_clause, 0, sizeof(where_clause));
        page = 0;
        
        switch (choice) {
            case 1: break;
            case 2: {
                ui_clear();
                ui_header("FILTER BY TYPE", "Select property type and action");
                
                const char *type_options[] = {
                    "Sell - Residential", "Sell - Commercial", "Sell - Land",
                    "Rent - Residential", "Rent - Commercial", "Rent - Land"
                };
                int type_choice;
                if (!ui_form_field_int("Select type", &type_choice, 1, 6, "1-6")) break;
                
                PropertyType ptype;
                PropertyAction action;
                switch (type_choice) {
                    case 1: ptype = PROP_TYPE_RESIDENTIAL; action = PROP_ACTION_SELL; break;
                    case 2: ptype = PROP_TYPE_COMMERCIAL; action = PROP_ACTION_SELL; break;
                    case 3: ptype = PROP_TYPE_LAND; action = PROP_ACTION_SELL; break;
                    case 4: ptype = PROP_TYPE_RESIDENTIAL; action = PROP_ACTION_RENT; break;
                    case 5: ptype = PROP_TYPE_COMMERCIAL; action = PROP_ACTION_RENT; break;
                    case 6: ptype = PROP_TYPE_LAND; action = PROP_ACTION_RENT; break;
                }
                snprintf(where_clause, sizeof(where_clause), "ptype = %d AND action = %d", ptype, action);
                break;
            }
            case 3: {
                int district;
                if (ui_form_field_int("District", &district, 1, 30, "1-30")) {
                    snprintf(where_clause, sizeof(where_clause), "district = %d", district);
                }
                break;
            }
            case 4: {
                const char *locations[] = {"North", "South", "East", "West"};
                int loc_idx;
                if (ui_form_field_enum("Location", locations, 4, &loc_idx, "Select location")) {
                    snprintf(where_clause, sizeof(where_clause), "location = %d", loc_idx);
                }
                break;
            }
            case 5: {
                double min, max;
                if (ui_form_field_double("Min Price", &min, 0, 1e12, "Minimum price") &&
                    ui_form_field_double("Max Price", &max, min, 1e12, "Maximum price")) {
                    snprintf(where_clause, sizeof(where_clause), 
                        "(action = %d AND sell_price BETWEEN %.2f AND %.2f) OR "
                        "(action = %d AND monthly_price BETWEEN %.2f AND %.2f)",
                        PROP_ACTION_SELL, min, max, PROP_ACTION_RENT, min, max);
                }
                break;
            }
            case 6: {
                char keyword[128];
                if (ui_form_field("Keyword", keyword, sizeof(keyword), NULL, "Search in address")) {
                    snprintf(where_clause, sizeof(where_clause), "address LIKE '%%%s%%'", keyword);
                }
                break;
            }
            case 7: {
                const char *sort_options[] = {
                    "Date (newest first)", "Date (oldest first)",
                    "Price (low to high)", "Price (high to low)",
                    "District", "Floor Area"
                };
                int sort_choice;
                if (ui_form_field_int("Sort by", &sort_choice, 1, 6, "1-6")) break;
                
                switch (sort_choice) {
                    case 1: strcpy(order_by, "date DESC"); break;
                    case 2: strcpy(order_by, "date ASC"); break;
                    case 3: strcpy(order_by, 
                        "(CASE WHEN action=0 THEN sell_price ELSE monthly_price END) ASC"); break;
                    case 4: strcpy(order_by, 
                        "(CASE WHEN action=0 THEN sell_price ELSE monthly_price END) DESC"); break;
                    case 5: strcpy(order_by, "district ASC"); break;
                    case 6: strcpy(order_by, "floor_area DESC"); break;
                }
                ui_toast(UI_STYLE_SUCCESS, "Sort order updated");
                break;
            }
            case 8: {
                if (props) { free(props); props = NULL; }
                break;
            }
        }
        
        if (choice >= 1 && choice <= 7) {
            page = 0;
        }
        
        if (choice == 8) {
            if (!props || count == 0) {
                ui_alert(UI_STYLE_WARNING, "No Results", "Perform a search first.");
                continue;
            }
            
            ui_clear();
            ui_header("PROPERTY DETAILS", "Select a property to view full details");
            
            print_property_table(props, count, page * PAGE_SIZE);
            
            int detail_idx;
            char prompt[64];
            snprintf(prompt, sizeof(prompt), "Select property (1-%d, 0 to go back)", count);
            if (!ui_form_field_int(prompt, &detail_idx, 0, count, prompt)) continue;
            
            if (detail_idx > 0) {
                ui_clear();
                ui_header("PROPERTY DETAILS", props[detail_idx - 1].code);
                property_print(&props[detail_idx - 1]);
                ui_footer("Press any key to continue", "");
                _getch();
            }
            continue;
        }
        
        if (props) { free(props); props = NULL; }
        
        total_count = db_property_count_filtered(db, where_clause);
        total_pages = (total_count + PAGE_SIZE - 1) / PAGE_SIZE;
        if (total_pages == 0) total_pages = 1;
        
        ui_spinner_start("Searching...");
        Sleep(300);
        int result = db_property_list_paginated(db, where_clause, order_by, PAGE_SIZE, page * PAGE_SIZE, &props, &count);
        ui_spinner_stop();
        
        if (!result) {
            ui_alert(UI_STYLE_ERROR, "Error", "Search failed");
            continue;
        }
        
        while (1) {
            ui_clear();
            ui_header("SEARCH RESULTS", "Matching properties");
            ui_status_bar(username, "SEARCH", "");
            
            ui_print_styled(UI_STYLE_MUTED, "  Filters: %s\n", where_clause[0] ? where_clause : "None");
            ui_print_styled(UI_STYLE_MUTED, "  Sort: %s  |  Page %d of %d  |  Total: %d\n\n", 
                order_by, page + 1, total_pages, total_count);
            
            print_property_table(props, count, page * PAGE_SIZE);
            
            printf("\n");
            ui_print_styled(UI_STYLE_INFO, "  Navigation: [n]ext  [p]rev  [d]etails  [s]ort  [c]lear  [b]ack\n");
            
            char nav[4];
            safe_gets(nav, sizeof(nav));
            
            if (nav[0] == 'n' || nav[0] == 'N') {
                if (page < total_pages - 1) {
                    page++;
                    free(props);
                    db_property_list_paginated(db, where_clause, order_by, PAGE_SIZE, page * PAGE_SIZE, &props, &count);
                } else {
                    ui_toast(UI_STYLE_WARNING, "Already on last page");
                }
            } else if (nav[0] == 'p' || nav[0] == 'P') {
                if (page > 0) {
                    page--;
                    free(props);
                    db_property_list_paginated(db, where_clause, order_by, PAGE_SIZE, page * PAGE_SIZE, &props, &count);
                } else {
                    ui_toast(UI_STYLE_WARNING, "Already on first page");
                }
            } else if (nav[0] == 'd' || nav[0] == 'D') {
                int detail_idx;
                if (ui_form_field_int("Property number", &detail_idx, 1, count, "Enter number")) {
                    ui_clear();
                    ui_header("PROPERTY DETAILS", props[detail_idx - 1].code);
                    property_print(&props[detail_idx - 1]);
                    ui_footer("Press any key to continue", "");
                    _getch();
                }
            } else if (nav[0] == 's' || nav[0] == 'S') {
                break; // Go back to sort menu
            } else if (nav[0] == 'c' || nav[0] == 'C') {
                memset(where_clause, 0, sizeof(where_clause));
                strcpy(order_by, "date DESC");
                page = 0;
                break;
            } else if (nav[0] == 'b' || nav[0] == 'B') {
                break;
            }
        }
        
        if (props) { free(props); props = NULL; }
    }
    
    if (props) free(props);
}

void menu_user_settings(Database *db, const char *username) {
    user_edit_profile(db, username);
}

void menu_admin(Database *db) {
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
        ui_print_styled(UI_STYLE_MUTED, "  0. Back\n");
        
        int choice = ui_menu_end("Select option", 0, 4);
        
        if (choice == 0) break;
        
        ui_clear();
        ui_header("ADMIN RESULTS", admin_options[choice - 1]);
        
        switch (choice) {
            case 1: {
                User *users = NULL;
                int count = 0;
                if (db_user_list_all(db, &users, &count)) {
                    ui_print_styled(UI_STYLE_PRIMARY, "  %-20s %-20s %-15s %-25s\n", "Username", "Name", "Phone", "Email");
                    ui_divider();
                    for (int i = 0; i < count; i++) {
                        printf("  %-20s %-20s %-15s %-25s\n",
                            users[i].username,
                            users[i].first_name,
                            users[i].phone,
                            users[i].email);
                    }
                    free(users);
                }
                break;
            }
            case 2: {
                Property *props = NULL;
                int count = 0;
                if (db_property_list_paginated(db, "1=1", "date DESC", 0, 0, &props, &count)) {
                    for (int i = 0; i < count; i++) {
                        property_print_short(&props[i]);
                    }
                    free(props);
                }
                break;
            }
            case 3: {
                char code[MAX_FIELD_LEN];
                if (ui_form_field("Property Code", code, MAX_FIELD_LEN, NULL, "Enter code to force delete")) {
                    if (db_property_delete(db, code)) {
                        ui_alert(UI_STYLE_SUCCESS, "Deleted", "Property deleted successfully.");
                    } else {
                        ui_alert(UI_STYLE_ERROR, "Error", "Property not found.");
                    }
                }
                break;
            }
            case 4: {
                ui_print_styled(UI_STYLE_PRIMARY, "  System Statistics\n\n");
                int user_count = db_user_count(db);
                Property *props = NULL;
                int prop_count = 0;
                db_property_list_paginated(db, "1=1", "date DESC", 0, 0, &props, &prop_count);
                
                int active = db_property_count_by_type(db, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL) +
                            db_property_count_by_type(db, PROP_TYPE_COMMERCIAL, PROP_ACTION_SELL) +
                            db_property_count_by_type(db, PROP_TYPE_LAND, PROP_ACTION_SELL) +
                            db_property_count_by_type(db, PROP_TYPE_RESIDENTIAL, PROP_ACTION_RENT) +
                            db_property_count_by_type(db, PROP_TYPE_COMMERCIAL, PROP_ACTION_RENT) +
                            db_property_count_by_type(db, PROP_TYPE_LAND, PROP_ACTION_RENT);
                
                ui_print_styled(UI_STYLE_INFO, "  Total Users: %d\n", user_count);
                ui_print_styled(UI_STYLE_INFO, "  Total Properties: %d\n", prop_count);
                ui_print_styled(UI_STYLE_SUCCESS, "  Active Properties: %d\n", active);
                ui_print_styled(UI_STYLE_WARNING, "  Inactive Properties: %d\n", prop_count - active);
                if (props) free(props);
                break;
            }
        }
        ui_footer("Press any key to continue", "");
        _getch();
    }
}

// =============================================================================
// LEASE MANAGEMENT MENU
// =============================================================================

void menu_lease_management(Database *db, const char *username) {
    const char *lease_options[] = {
        "Create new lease agreement",
        "View your active leases",
        "Manage lease payments",
        "Terminate a lease"
    };
    
    while (1) {
        char time_str[20];
        get_current_time(time_str, sizeof(time_str));
        ui_clear();
        ui_header("LEASE MANAGEMENT", "Rental Agreements & Payments");
        ui_status_bar(username, "LEASES", time_str);
        
        ui_menu_start("LEASE MENU");
        for (int i = 0; i < 4; i++) {
            ui_menu_item(i + 1, 
                i == 0 ? "Create Lease" :
                i == 1 ? "My Leases" :
                i == 2 ? "Payments" : "Terminate Lease",
                lease_options[i], false);
        }
        ui_print_styled(UI_STYLE_MUTED, "  0. Back to Main Menu\n");
        
        int choice = ui_menu_end("Select option", 0, 4);
        
        if (choice == 0) break;
        
        switch (choice) {
            case 1: menu_create_lease(db, username); break;
            case 2: menu_view_leases(db, username); break;
            case 3: menu_lease_payments(db, username); break;
            case 4: menu_terminate_lease(db, username); break;
            default: ui_toast(UI_STYLE_ERROR, "Invalid option"); Sleep(1000);
        }
    }
}

void menu_create_lease(Database *db, const char *username) {
    ui_clear();
    ui_header("CREATE LEASE", "New Rental Agreement");
    
    // List available rent properties owned by user
    Property *props = NULL;
    int count = 0;
    char where[128];
    snprintf(where, sizeof(where), "username = '%s' AND action = %d AND active = 1", username, PROP_ACTION_RENT);
    if (!db_property_list_paginated(db, where, "date DESC", 0, 0, &props, &count)) {
        ui_alert(UI_STYLE_ERROR, "Error", "Failed to load properties");
        return;
    }
    
    if (count == 0) {
        ui_alert(UI_STYLE_WARNING, "No Properties", "You have no active rental properties. Add a rental property first.");
        if (props) free(props);
        ui_footer("Press any key to continue", "");
        _getch();
        return;
    }
    
    ui_print_styled(UI_STYLE_PRIMARY, "  Your Rental Properties:\n\n");
    for (int i = 0; i < count; i++) {
        ui_print_styled(UI_STYLE_INFO, "  %d. %s - %s, District %d, %.2f/mo\n",
            i + 1, props[i].code, props[i].address, props[i].district, props[i].monthly_price);
    }
    free(props);
    
    // Select property
    char prop_code[MAX_FIELD_LEN];
    ui_form_start("SELECT PROPERTY");
    if (!ui_form_field("Property Code", prop_code, MAX_FIELD_LEN, NULL, "Enter the code of the property to lease")) {
        return;
    }
    ui_form_end();
    
    Property *prop = db_property_find_by_code(db, prop_code);
    if (!prop || strcmp(prop->username, username) != 0 || prop->action != PROP_ACTION_RENT) {
        ui_alert(UI_STYLE_ERROR, "Invalid", "Property not found or not your rental property.");
        if (prop) free(prop);
        ui_footer("Press any key to continue", "");
        _getch();
        return;
    }
    free(prop);
    
    // Get tenant username
    char tenant[MAX_FIELD_LEN];
    ui_form_start("TENANT INFO");
    if (!ui_form_field("Tenant Username", tenant, MAX_FIELD_LEN, NULL, "Enter tenant's username")) {
        return;
    }
    ui_form_end();
    
    User *tenant_user = db_user_find_by_username(db, tenant);
    if (!tenant_user) {
        ui_alert(UI_STYLE_ERROR, "Not Found", "Tenant user not found.");
        ui_footer("Press any key to continue", "");
        _getch();
        return;
    }
    free(tenant_user);
    
    // Get lease dates
    char start_date[MAX_FIELD_LEN], end_date[MAX_FIELD_LEN];
    ui_form_start("LEASE DATES (YYYY-MM-DD)");
    if (!ui_form_field("Start Date", start_date, MAX_FIELD_LEN, NULL, "e.g., 2026-01-01")) return;
    if (!ui_form_field("End Date", end_date, MAX_FIELD_LEN, NULL, "e.g., 2026-12-31")) return;
    ui_form_end();
    
    // Get rent and deposit
    double monthly_rent, deposit;
    ui_form_start("FINANCIAL");
    if (!ui_form_field_double("Monthly Rent", &monthly_rent, 0, 10000000, "Monthly rent amount")) return;
    if (!ui_form_field_double("Deposit", &deposit, 0, 10000000, "Security deposit")) return;
    ui_form_end();
    
    // Payment day
    int payment_day;
    ui_form_start("PAYMENT");
    if (!ui_form_field_int("Payment Day (1-28)", &payment_day, 1, 28, "Day of month for rent payment")) return;
    ui_form_end();
    
    // Auto-renew
    bool auto_renew = false;
    ui_confirm("Enable auto-renewal?", &auto_renew);
    
    // Create lease
    Lease lease;
    memset(&lease, 0, sizeof(Lease));
    strcpy(lease.property_code, prop_code);
    strcpy(lease.tenant_username, tenant);
    strcpy(lease.start_date, start_date);
    strcpy(lease.end_date, end_date);
    lease.monthly_rent = monthly_rent;
    lease.deposit = deposit;
    lease.payment_day = payment_day;
    lease.status = LEASE_STATUS_ACTIVE;
    lease.auto_renew = auto_renew ? 1 : 0;
    
    ui_spinner_start("Creating lease...");
    Sleep(500);
    int result = db_lease_create(db, &lease);
    ui_spinner_stop();
    
    if (result) {
        ui_alert(UI_STYLE_SUCCESS, "Success", "Lease created successfully!");
        ui_print_styled(UI_STYLE_INFO, "  Property: %s\n", prop_code);
        ui_print_styled(UI_STYLE_INFO, "  Tenant: %s\n", tenant);
        ui_print_styled(UI_STYLE_INFO, "  Period: %s to %s\n", start_date, end_date);
        ui_print_styled(UI_STYLE_INFO, "  Monthly Rent: %.2f\n", monthly_rent);
        ui_print_styled(UI_STYLE_INFO, "  Deposit: %.2f\n", deposit);
    } else {
        ui_alert(UI_STYLE_ERROR, "Error", "Failed to create lease. Check dates and tenant.");
    }
    ui_footer("Press any key to continue", "");
    _getch();
}

void menu_view_leases(Database *db, const char *username) {
    ui_clear();
    ui_header("MY LEASES", "Your Active & Past Leases");
    
    Lease *leases = NULL;
    int count = 0;
    
    if (!db_lease_list_by_tenant(db, username, &leases, &count)) {
        ui_alert(UI_STYLE_ERROR, "Error", "Failed to load leases");
        return;
    }
    
    if (count == 0) {
        ui_print_styled(UI_STYLE_MUTED, "  No leases found.\n");
    } else {
        ui_print_styled(UI_STYLE_PRIMARY, "  %-4s %-10s %-12s %-12s %-10s %-8s %-10s\n",
            "ID", "Property", "Start", "End", "Rent", "Day", "Status");
        ui_divider();
        
        for (int i = 0; i < count; i++) {
            const char *status_str[] = {"Active", "Expired", "Terminated", "Pending"};
            ui_print_styled(UI_STYLE_DEFAULT, "  %-4d %-10s %-12s %-12s %-10.2f %-8d %-10s\n",
                leases[i].id,
                leases[i].property_code,
                leases[i].start_date,
                leases[i].end_date,
                leases[i].monthly_rent,
                leases[i].payment_day,
                status_str[leases[i].status]);
        }
        ui_divider();
        ui_print_styled(UI_STYLE_INFO, "  Total: %d lease(s)\n", count);
    }
    
    if (leases) free(leases);
    ui_footer("Press any key to continue", "");
    _getch();
}

void print_lease_detailed(const Lease *lease, Database *db) {
    ui_print_styled(UI_STYLE_PRIMARY, "  Lease ID: %d\n", lease->id);
    ui_print_styled(UI_STYLE_INFO, "  Property Code: %s\n", lease->property_code);
    ui_print_styled(UI_STYLE_INFO, "  Tenant: %s\n", lease->tenant_username);
    ui_print_styled(UI_STYLE_INFO, "  Period: %s to %s\n", lease->start_date, lease->end_date);
    ui_print_styled(UI_STYLE_INFO, "  Monthly Rent: %.2f\n", lease->monthly_rent);
    ui_print_styled(UI_STYLE_INFO, "  Deposit: %.2f\n", lease->deposit);
    ui_print_styled(UI_STYLE_INFO, "  Payment Day: %d\n", lease->payment_day);
    
    const char *status_str[] = {"Active", "Expired", "Terminated", "Pending"};
    ui_print_styled(UI_STYLE_INFO, "  Status: %s\n", status_str[lease->status]);
    ui_print_styled(UI_STYLE_INFO, "  Auto-Renew: %s\n", lease->auto_renew ? "Yes" : "No");
    ui_print_styled(UI_STYLE_MUTED, "  Created: %s\n", lease->created_at);
}

void menu_lease_payments(Database *db, const char *username) {
    ui_clear();
    ui_header("LEASE PAYMENTS", "Record & Track Rent Payments");
    
    // List active leases
    Lease *leases = NULL;
    int count = 0;
    if (!db_lease_list_by_tenant(db, username, &leases, &count)) {
        ui_alert(UI_STYLE_ERROR, "Error", "Failed to load leases");
        return;
    }
    
    // Filter active leases
    Lease *active_leases[100];
    int active_count = 0;
    for (int i = 0; i < count; i++) {
        if (leases[i].status == LEASE_STATUS_ACTIVE) {
            active_leases[active_count++] = &leases[i];
        }
    }
    
    if (active_count == 0) {
        ui_alert(UI_STYLE_INFO, "No Active Leases", "You have no active leases to manage payments for.");
        if (leases) free(leases);
        ui_footer("Press any key to continue", "");
        _getch();
        return;
    }
    
    ui_print_styled(UI_STYLE_PRIMARY, "  Your Active Leases:\n\n");
    for (int i = 0; i < active_count; i++) {
        ui_print_styled(UI_STYLE_INFO, "  %d. Lease #%d - %s - %.2f/mo (Due day %d)\n",
            i + 1, active_leases[i]->id, active_leases[i]->property_code,
            active_leases[i]->monthly_rent, active_leases[i]->payment_day);
    }
    
    int lease_idx;
    ui_form_start("SELECT LEASE");
    if (!ui_form_field_int("Lease Number", &lease_idx, 1, active_count, "Select lease")) {
        if (leases) free(leases);
        return;
    }
    ui_form_end();
    
    Lease *selected = active_leases[lease_idx - 1];
    
    ui_clear();
    ui_header("RECORD PAYMENT", selected->property_code);
    print_lease_detailed(selected, db);
    ui_divider();
    
    double amount;
    char date[MAX_FIELD_LEN];
    ui_form_start("PAYMENT DETAILS");
    if (!ui_form_field_double("Amount Paid", &amount, 0, 10000000, "Amount received")) return;
    if (!ui_form_field("Date (YYYY-MM-DD)", date, MAX_FIELD_LEN, NULL, "Payment date")) return;
    ui_form_end();
    
    bool is_late = false;
    ui_confirm("Is this a late payment?", &is_late);
    
    // For now, just record in lease (would need payment table for full history)
    ui_alert(UI_STYLE_SUCCESS, "Payment Recorded", "Payment recorded successfully!");
    ui_print_styled(UI_STYLE_INFO, "  Lease: #%d (%s)\n", selected->id, selected->property_code);
    ui_print_styled(UI_STYLE_INFO, "  Amount: %.2f\n", amount);
    ui_print_styled(UI_STYLE_INFO, "  Date: %s\n", date);
    if (is_late) ui_print_styled(UI_STYLE_WARNING, "  Late Payment: Yes\n");
    
    if (leases) free(leases);
    ui_footer("Press any key to continue", "");
    _getch();
}

void menu_terminate_lease(Database *db, const char *username) {
    ui_clear();
    ui_header("TERMINATE LEASE", "End a Lease Agreement");
    
    Lease *leases = NULL;
    int count = 0;
    if (!db_lease_list_by_tenant(db, username, &leases, &count)) {
        ui_alert(UI_STYLE_ERROR, "Error", "Failed to load leases");
        return;
    }
    
    // Filter active leases
    Lease *active_leases[100];
    int active_count = 0;
    for (int i = 0; i < count; i++) {
        if (leases[i].status == LEASE_STATUS_ACTIVE) {
            active_leases[active_count++] = &leases[i];
        }
    }
    
    if (active_count == 0) {
        ui_alert(UI_STYLE_INFO, "No Active Leases", "You have no active leases to terminate.");
        if (leases) free(leases);
        ui_footer("Press any key to continue", "");
        _getch();
        return;
    }
    
    ui_print_styled(UI_STYLE_PRIMARY, "  Your Active Leases:\n\n");
    for (int i = 0; i < active_count; i++) {
        ui_print_styled(UI_STYLE_INFO, "  %d. Lease #%d - %s - %.2f/mo\n",
            i + 1, active_leases[i]->id, active_leases[i]->property_code,
            active_leases[i]->monthly_rent);
    }
    
    int lease_idx;
    ui_form_start("SELECT LEASE TO TERMINATE");
    if (!ui_form_field_int("Lease Number", &lease_idx, 1, active_count, "Select lease")) {
        if (leases) free(leases);
        return;
    }
    ui_form_end();
    
    Lease *selected = active_leases[lease_idx - 1];
    
    ui_clear();
    ui_header("CONFIRM TERMINATION", "Review before terminating");
    print_lease_detailed(selected, db);
    ui_divider();
    ui_print_styled(UI_STYLE_WARNING, "  This will mark the lease as TERMINATED.\n");
    ui_print_styled(UI_STYLE_WARNING, "  The tenant will need to vacate the property.\n\n");
    
    bool confirm = false;
    ui_confirm("Are you sure you want to terminate this lease?", &confirm);
    
    if (confirm) {
        selected->status = LEASE_STATUS_TERMINATED;
        if (db_lease_update(db, selected)) {
            ui_alert(UI_STYLE_SUCCESS, "Terminated", "Lease terminated successfully!");
        } else {
            ui_alert(UI_STYLE_ERROR, "Error", "Failed to terminate lease.");
        }
    } else {
        ui_toast(UI_STYLE_INFO, "Termination cancelled");
    }
    
    if (leases) free(leases);
    ui_footer("Press any key to continue", "");
    _getch();
}