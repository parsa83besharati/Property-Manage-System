#include "database.h"
#include "audit.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    char db_path[100];
    sprintf(db_path, "data/test_audit_debug6.db");
    
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
    
    // Test the audit_get_logs function step by step
    char sql[1024];
    int written = snprintf(sql, sizeof(sql), "SELECT timestamp, username, action, entity, entity_id, details FROM audit_log WHERE 1=1");
    printf("Initial written: %d, sql: %s\n", written, sql);
    
    const char *username = "testuser";
    if (username && strlen(username) > 0) {
        int w = snprintf(sql + written, sizeof(sql) - written, " AND username = '%s'", username);
        printf("After username: w=%d, written=%d, sql: %s\n", w, written, sql);
        if (w < 0 || written + w >= (int)sizeof(sql)) return 0;
        written += w;
    }
    
    int action = -1;
    if (action >= 0) {
        int w = snprintf(sql + written, sizeof(sql) - written, " AND action = %d", action);
        written += w;
    }
    int entity = -1;
    if (entity >= 0) {
        int w = snprintf(sql + written, sizeof(sql) - written, " AND entity = %d", entity);
        written += w;
    }
    
    int w = snprintf(sql + written, sizeof(sql) - written, " ORDER BY timestamp DESC");
    written += w;
    
    int limit = 10;
    if (limit > 0) {
        w = snprintf(sql + written, sizeof(sql) - written, " LIMIT %d", limit);
        written += w;
    }
    
    printf("Final SQL: %s\n", sql);
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Prepare failed: %s\n", sqlite3_errmsg(db->db));
        return 1;
    }
    
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
        printf("Row found!\n");
    }
    sqlite3_finalize(stmt);
    printf("Manual count: %d\n", count);
    
    database_close(db);
    return 0;
}