#include "database.h"
#include "audit.h"
#include <stdio.h>

int main(void) {
    char db_path[100];
    sprintf(db_path, "data/test_audit_debug2.db");
    
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
    
    char **logs = NULL;
    int count = 0;
    int r3 = audit_get_logs(db, "testuser", -1, -1, NULL, 10, 0, &logs, &count);
    printf("Get logs: %d, count: %d\n", r3, count);
    
    for (int i = 0; i < count; i++) {
        printf("Log %d: %s\n", i, logs[i]);
        free(logs[i]);
    }
    if (logs) free(logs);
    
    database_close(db);
    return 0;
}