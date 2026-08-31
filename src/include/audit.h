#ifndef AUDIT_H
#define AUDIT_H

#include "database.h"

typedef enum {
    AUDIT_CREATE,
    AUDIT_UPDATE,
    AUDIT_DELETE,
    AUDIT_LOGIN,
    AUDIT_LOGOUT,
    AUDIT_EXPORT,
    AUDIT_IMPORT
} AuditAction;

typedef enum {
    AUDIT_ENTITY_USER,
    AUDIT_ENTITY_PROPERTY,
    AUDIT_ENTITY_SYSTEM
} AuditEntity;

int audit_log(Database *db, const char *username, AuditAction action, AuditEntity entity, const char *entity_id, const char *details);
int audit_get_logs(Database *db, const char *username, AuditAction action, AuditEntity entity, const char *entity_id, int limit, int offset, char ***logs, int *count);
int audit_log_init_schema(Database *db);

#endif