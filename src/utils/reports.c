#include "reports.h"
#include "database.h"
#include "export.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// =============================================================================
// RENT ROLL REPORT
// =============================================================================

int generate_rent_roll_report(Database *db, const char *filename) {
    if (!db || !filename) return 0;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) return 0;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char date_str[64];
    strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(fp, "RENT ROLL REPORT\n");
    fprintf(fp, "Generated: %s\n\n", date_str);
    
    // Get all active leases
    Lease *leases = NULL;
    int lease_count = 0;
    if (!db_lease_list_all(db, &leases, &lease_count)) {
        fclose(fp);
        return 0;
    }
    
    // Filter active leases
    Lease *active_leases = malloc(lease_count * sizeof(Lease));
    int active_count = 0;
    for (int i = 0; i < lease_count; i++) {
        if (leases[i].status == LEASE_STATUS_ACTIVE) {
            active_leases[active_count++] = leases[i];
        }
    }
    free(leases);
    
    if (active_count == 0) {
        fprintf(fp, "No active leases found.\n");
        fclose(fp);
        free(active_leases);
        return 1;
    }
    
    // Header
    fprintf(fp, "%-10s %-15s %-15s %-12s %-12s %-10s %-10s %-10s %-10s\n",
            "Lease ID", "Property", "Tenant", "Start Date", "End Date", 
            "Monthly Rent", "Deposit", "Pmt Day", "Status");
    fprintf(fp, "------------------------------------------------------------------------------------------------------------------------\n");
    
    double total_monthly_rent = 0.0;
    double total_deposits = 0.0;
    
    const char *status_str[] = {"Active", "Expired", "Terminated", "Pending"};
    
    for (int i = 0; i < active_count; i++) {
        Lease *l = &active_leases[i];
        fprintf(fp, "%-10d %-15s %-15s %-12s %-12s %-10.2f %-10.2f %-10d %-10s\n",
                l->id, l->property_code, l->tenant_username,
                l->start_date, l->end_date,
                l->monthly_rent, l->deposit, l->payment_day,
                status_str[l->status]);
        total_monthly_rent += l->monthly_rent;
        total_deposits += l->deposit;
    }
    
    fprintf(fp, "\n");
    fprintf(fp, "SUMMARY:\n");
    fprintf(fp, "Total Active Leases: %d\n", active_count);
    fprintf(fp, "Total Monthly Rent: %.2f\n", total_monthly_rent);
    fprintf(fp, "Total Deposits Held: %.2f\n", total_deposits);
    fprintf(fp, "Annualized Rent: %.2f\n", total_monthly_rent * 12);
    
    free(active_leases);
    fclose(fp);
    return 1;
}

// =============================================================================
// EXPENSE REPORT
// =============================================================================

int generate_expense_report(Database *db, const char *filename) {
    if (!db || !filename) return 0;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) return 0;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char date_str[64];
    strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(fp, "EXPENSE REPORT\n");
    fprintf(fp, "Generated: %s\n\n", date_str);
    
    Expense *expenses = NULL;
    int count = 0;
    if (!db_expense_list_all(db, &expenses, &count)) {
        fclose(fp);
        return 0;
    }
    
    if (count == 0) {
        fprintf(fp, "No expenses found.\n");
        fclose(fp);
        return 1;
    }
    
    const char *type_str[] = {
        "Mortgage", "Insurance", "Utilities", "HOA", 
        "Maintenance", "Tax", "Other"
    };
    
    // Summary by type
    double type_totals[7] = {0};
    double grand_total = 0.0;
    
    for (int i = 0; i < count; i++) {
        Expense *e = &expenses[i];
        if (e->type >= 0 && e->type <= 6) {
            type_totals[e->type] += e->amount;
        }
        grand_total += e->amount;
    }
    
    fprintf(fp, "EXPENSE SUMMARY BY TYPE:\n");
    fprintf(fp, "%-15s %12s\n", "Type", "Amount");
    fprintf(fp, "---------------------------\n");
    const char *type_str_short[] = {"Mortgage", "Insurance", "Utilities", "HOA", "Maintenance", "Tax", "Other"};
    for (int t = 0; t < 7; t++) {
        if (type_totals[t] > 0) {
            fprintf(fp, "%-15s %12.2f\n", type_str_short[t], type_totals[t]);
        }
    }
    fprintf(fp, "---------------------------\n");
    fprintf(fp, "%-15s %12.2f\n\n", "TOTAL", grand_total);
    
    // Detailed listing
    fprintf(fp, "DETAILED EXPENSE LISTING:\n");
    fprintf(fp, "%-5s %-15s %-12s %10s %-12s %-20s %-15s\n",
            "ID", "Property", "Type", "Amount", "Date", "Description", "Vendor");
    fprintf(fp, "-----------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < count; i++) {
        Expense *e = &expenses[i];
        const char *type_name = (e->type >= 0 && e->type <= 6) ? 
            (e->type == 0 ? "Mortgage" : e->type == 1 ? "Insurance" : 
             e->type == 2 ? "Utilities" : e->type == 3 ? "HOA" : 
             e->type == 4 ? "Maintenance" : e->type == 5 ? "Tax" : "Other") : "Unknown";
        
        fprintf(fp, "%-5d %-15s %-12s %10.2f %-12s %-20s %-15s\n",
                e->id, e->property_code, 
                (e->type >= 0 && e->type <= 6) ? "Mortgage" : "Unknown",
                e->amount, e->date, e->description, e->vendor);
    }
    
    fprintf(fp, "\n");
    fprintf(fp, "Total Expenses: %.2f\n", grand_total);
    
    free(expenses);
    fclose(fp);
    return 1;
}

// =============================================================================
// PROPERTY SUMMARY REPORT
// =============================================================================

int generate_property_summary_report(Database *db, const char *filename) {
    if (!db || !filename) return 0;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) return 0;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char date_str[64];
    strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(fp, "PROPERTY PORTFOLIO SUMMARY\n");
    fprintf(fp, "Generated: %s\n\n", date_str);
    
    // Get all properties
    Property *props = NULL;
    int prop_count = 0;
    if (!db_property_list_all(db, &props, &prop_count)) {
        fclose(fp);
        return 0;
    }
    
    int active_count = 0;
    int sell_count = 0, rent_count = 0;
    double total_sell_value = 0.0, total_rent_income = 0.0;
    
    fprintf(fp, "%-10s %-12s %-8s %-10s %-12s %12s\n",
            "Code", "Type", "Action", "District", "Status", "Value/Rent");
    fprintf(fp, "---------------------------------------------------------------\n");
    
    for (int i = 0; i < prop_count; i++) {
        Property *p = &props[i];
        if (p->active) active_count++;
        if (p->action == PROP_ACTION_SELL) {
            sell_count++;
            total_sell_value += p->sell_price;
        } else {
            rent_count++;
            total_rent_income += p->monthly_price;
        }
        
        const char *type_str[] = {"Residential", "Commercial", "Land"};
        const char *action_str[] = {"Sell", "Rent"};
        const char *status = p->active ? "Active" : "Inactive";
        
        fprintf(fp, "%-10s %-12s %-8s %-10d %-10s %12.2f\n",
                p->code, type_str[p->ptype], action_str[p->action],
                p->district, status,
                p->action == PROP_ACTION_SELL ? p->sell_price : p->monthly_price);
    }
    
    fprintf(fp, "\nPORTFOLIO SUMMARY:\n");
    fprintf(fp, "Total Properties: %d\n", prop_count);
    fprintf(fp, "Active: %d | Inactive: %d\n", active_count, prop_count - active_count);
    fprintf(fp, "For Sale: %d (Total Value: %.2f)\n", sell_count, total_sell_value);
    fprintf(fp, "For Rent: %d (Monthly Income: %.2f)\n", rent_count, total_rent_income);
    fprintf(fp, "Annualized Rental Income: %.2f\n", total_rent_income * 12);
    
    free(props);
    fclose(fp);
    return 1;
}