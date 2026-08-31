#include "database.h"
#include "audit.h"
#include <stdio.h>

static const char *action_to_string(int action) {
    switch (action) {
        case 0: return "CREATE";
        case 1: return "UPDATE";
        case 2: return "DELETE";
        case 3: return "LOGIN";
        case 4: return "LOGOUT";
        case 5: return "EXPORT";
        case 6: return "IMPORT";
        default: return "UNKNOWN";
    }
}

static const char *entity_to_string(int entity) {
    switch (entity) {
        case 0: return "USER";
        case 1: return "PROPERTY";
        case 2: return "SYSTEM";
        default: return "UNKNOWN";
    }
}

int main(void) {
    char db_path[100];
    sprintf(db_path, "data/test_audit_debug3.db");
    
    #ifdef _WIN32
    _mkdir("data");
    #else
    mkdir("data", 0755);
    #endif
    
    Database *db = database_open(db_path);
    if (!db) {
        printf("Failed to open database\n");
        return 1;
    }
    printf("Database opened\n");
    
    int r = database_init_schema(db);
    printf("Schema init: %d\n", r);
    
    int r2 = audit_log(db, "testuser", 0, 1, "TEST001", "Test audit");
    printf("Audit log: %d\n", r2);
    
    // Manually check the database
    const char *sql = "SELECT * FROM audit_log";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Prepare failed: %s\n", sqlite3_errmsg(db->db));
        return 1;
    }
    
    printf("Direct query results:\n");
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *timestamp = (const char *)sqlite3_column_text(stmt, 0);
        const char *uname = (const char *)sqlite3_column_text(stmt, 1);
        int action_val = sqlite3_column_int(stmt, 2);
        int entity_val = sqlite3_column_int(stmt, 3);
        const char *eid = (const char *)sqlite3_column_text(stmt, 4);
        const char *details = (const char *)sqlite3_column_text(stmt, 5);
        printf("Row: %s | %s | %d | %d | %s | %s\n", 
               timestamp ? timestamp : "NULL",
               uname ? uname : "NULL",
               action_val, entity_val,
               eid ? eid : "NULL",
               details ? details : "NULL");
    }
    sqlite3_finalize(stmt);
    
    database_close(db);
    return 0;
}