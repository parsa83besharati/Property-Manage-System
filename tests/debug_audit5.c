#include "database.h"
#include "audit.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    char db_path[100];
    sprintf(db_path, "data/test_audit_debug5.db");
    
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
    
    // Test the SQL query that audit_get_logs generates
    char sql[1024];
    char *ptr = sql;
    int remaining = 1024;
    
    ptr += snprintf(ptr, remaining, "SELECT timestamp, username, action, entity, entity_id, details FROM audit_log WHERE 1=1");
    remaining -= (ptr - sql);
    
    const char *username = "testuser";
    if (username && strlen(username) > 0) {
        ptr += snprintf(ptr, remaining, " AND username = '%s'", username);
        remaining -= (ptr - sql);
    }
    int action = -1;
    if (action >= 0) {
        ptr += snprintf(ptr, remaining, " AND action = %d", action);
        remaining -= (ptr - sql);
    }
    int entity = -1;
    if (entity >= 0) {
        ptr += snprintf(ptr, remaining, " AND entity = %d", entity);
        remaining -= (ptr - sql);
    }
    
    ptr += snprintf(ptr, remaining, " ORDER BY timestamp DESC");
    remaining -= (ptr - sql);
    
    int limit = 10;
    if (limit > 0) {
        ptr += snprintf(ptr, remaining, " LIMIT %d", limit);
        remaining -= (ptr - sql);
    }
    
    printf("Testing the exact same SQL:\n%s\n", sql);
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Prepare failed: %s\n", sqlite3_errmsg(db->db));
        return 1;
    }
    
    printf("Testing the exact same SQL:\n%s\n", sql);
    
    int manual_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        manual_count++;
        printf("Row found!\n");
    }
    sqlite3_finalize(stmt);
    printf("Manual count: %d\n", manual_count);
    
    database_close(db);
    return 0;
}