#include "audit.h"
#include "database.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *AUDIT_SCHEMA_SQL = 
    "CREATE TABLE IF NOT EXISTS audit_log ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "    username TEXT NOT NULL,"
    "    action INTEGER NOT NULL,"
    "    entity INTEGER NOT NULL,"
    "    entity_id TEXT,"
    "    details TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username);"
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);"
    "CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity, entity_id);";

int audit_log_init_schema(Database *db) {
    if (!db) return 0;
    char *err_msg = NULL;
    int rc = sqlite3_exec(db->db, AUDIT_SCHEMA_SQL, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Audit schema creation failed: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    return 1;
}

static const char *action_to_string(AuditAction action) {
    switch (action) {
        case AUDIT_CREATE: return "CREATE";
        case AUDIT_UPDATE: return "UPDATE";
        case AUDIT_DELETE: return "DELETE";
        case AUDIT_LOGIN: return "LOGIN";
        case AUDIT_LOGOUT: return "LOGOUT";
        case AUDIT_EXPORT: return "EXPORT";
        case AUDIT_IMPORT: return "IMPORT";
        default: return "UNKNOWN";
    }
}

static const char *entity_to_string(AuditEntity entity) {
    switch (entity) {
        case AUDIT_ENTITY_USER: return "USER";
        case AUDIT_ENTITY_PROPERTY: return "PROPERTY";
        case AUDIT_ENTITY_SYSTEM: return "SYSTEM";
        default: return "UNKNOWN";
    }
}

int audit_log(Database *db, const char *username, AuditAction action, AuditEntity entity, const char *entity_id, const char *details) {
    if (!db || !username) return 0;
    
    const char *sql = "INSERT INTO audit_log (username, action, entity, entity_id, details) VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "audit_log prepare failed: %s\n", sqlite3_errmsg(db->db));
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, action);
    sqlite3_bind_int(stmt, 3, entity);
    sqlite3_bind_text(stmt, 4, entity_id ? entity_id : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, details ? details : "", -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

int audit_get_logs(Database *db, const char *username, AuditAction action, AuditEntity entity, const char *entity_id, int limit, int offset, char ***logs, int *count) {
    if (!db || !logs || !count) return 0;
    
    char sql[1024];
    int written = snprintf(sql, sizeof(sql), "SELECT timestamp, username, action, entity, entity_id, details FROM audit_log WHERE 1=1");
    if (written < 0 || written >= (int)sizeof(sql)) return 0;
    
    if (username && strlen(username) > 0) {
        int w = snprintf(sql + written, sizeof(sql) - written, " AND username = '%s'", username);
        if (w < 0 || written + w >= (int)sizeof(sql)) return 0;
        written += w;
    }
    if (action != -1) {
        int w = snprintf(sql + written, sizeof(sql) - written, " AND action = %d", action);
        if (w < 0 || written + w >= (int)sizeof(sql)) return 0;
        written += w;
    }
    if (entity != -1) {
        int w = snprintf(sql + written, sizeof(sql) - written, " AND entity = %d", entity);
        if (w < 0 || written + w >= (int)sizeof(sql)) return 0;
        written += w;
    }
    if (entity_id && strlen(entity_id) > 0) {
        int w = snprintf(sql + written, sizeof(sql) - written, " AND entity_id = '%s'", entity_id);
        if (w < 0 || written + w >= (int)sizeof(sql)) return 0;
        written += w;
    }
    
    int w = snprintf(sql + written, sizeof(sql) - written, " ORDER BY timestamp DESC");
    if (w < 0 || written + w >= (int)sizeof(sql)) return 0;
    written += w;
    
    if (limit > 0) {
        w = snprintf(sql + written, sizeof(sql) - written, " LIMIT %d", limit);
        if (w < 0 || written + w >= (int)sizeof(sql)) return 0;
        written += w;
        if (offset > 0) {
            w = snprintf(sql + written, sizeof(sql) - written, " OFFSET %d", offset);
            if (w < 0 || written + w >= (int)sizeof(sql)) return 0;
            written += w;
        }
    }
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "audit_get_logs: prepare failed: %s\n", sqlite3_errmsg(db->db));
        return 0;
    }
    fprintf(stderr, "audit_get_logs: SQL = %s\n", sql);
    
    int capacity = 100;
    *logs = malloc(capacity * sizeof(char *));
    *count = 0;
    
    int step_result;
    while ((step_result = sqlite3_step(stmt)) == SQLITE_ROW) {
        fprintf(stderr, "audit_get_logs: row found\n");
        if (*count >= capacity) {
            capacity *= 2;
            *logs = realloc(*logs, capacity * sizeof(char *));
        }
        
        const char *timestamp = (const char *)sqlite3_column_text(stmt, 0);
        const char *uname = (const char *)sqlite3_column_text(stmt, 1);
        int action_val = sqlite3_column_int(stmt, 2);
        int entity_val = sqlite3_column_int(stmt, 3);
        const char *eid = (const char *)sqlite3_column_text(stmt, 4);
        const char *details = (const char *)sqlite3_column_text(stmt, 5);
        
        char *log_entry = malloc(512);
        snprintf(log_entry, 512, "[%s] %s %s %s: %s", 
                 timestamp ? timestamp : "",
                 uname ? uname : "",
                 action_to_string(action_val),
                 entity_to_string(entity_val),
                 details ? details : "");
        
        (*logs)[(*count)++] = log_entry;
    }
    
    sqlite3_finalize(stmt);
    return 1;
}