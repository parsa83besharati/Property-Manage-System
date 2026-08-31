#include "unity.h"
#include "database.h"
#include "audit.h"
#include "user.h"
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void setUp(void) {}
void tearDown(void) {}

void cleanup_db(const char *path) {
    char full_path[300];
    snprintf(full_path, sizeof(full_path), "data/%s", path);
    remove(full_path);
    char buf[300];
    snprintf(buf, sizeof(buf), "%s-shm", full_path); remove(buf);
    snprintf(buf, sizeof(buf), "%s-wal", full_path); remove(buf);
}

Database *open_test_db(const char *path) {
    char full_path[300];
    snprintf(full_path, sizeof(full_path), "data/%s", path);
    cleanup_db(path);
    Database *db = database_open(full_path);
    if (!db) {
        printf("Failed to open database: %s\n", full_path);
        return NULL;
    }
    if (!database_init_schema(db)) {
        printf("Failed to init schema\n");
        database_close(db);
        return NULL;
    }
    User u;
    memset(&u, 0, sizeof(User));
    strcpy(u.username, "testuser");
    strcpy(u.first_name, "Test");
    strcpy(u.last_name, "User");
    strcpy(u.id, "1234567890");
    strcpy(u.phone, "09123456789");
    strcpy(u.email, "test@example.com");
    strcpy(u.password_hash, "hash");
    strcpy(u.salt, "salt");
    int r = db_user_create(db, &u);
    printf("User create: %d\n", r);
    if (r == 0) {
        database_close(db);
        return NULL;
    }
    return db;
}

void test_audit_log_basic(void) {
    char db_path[100];
    sprintf(db_path, "test_audit_%d.db", rand());
    Database *db = open_test_db(db_path);
    TEST_ASSERT_NOT_NULL(db);
    
    int r = audit_log(db, "testuser", AUDIT_CREATE, AUDIT_ENTITY_PROPERTY, "PROP001", "Created property");
    printf("audit_log returned: %d\n", r);
    TEST_ASSERT_EQUAL(1, r);
    
    char **logs = NULL;
    int count = 0;
    r = audit_get_logs(db, "testuser", -1, -1, NULL, 10, 0, &logs, &count);
    printf("audit_get_logs returned: %d, count: %d\n", r, count);
    TEST_ASSERT_EQUAL(1, r);
    TEST_ASSERT_EQUAL_INT(1, count);
    if (count > 0) {
        printf("Log: %s\n", logs[0]);
        TEST_ASSERT_TRUE(strstr(logs[0], "CREATE") != NULL);
        TEST_ASSERT_TRUE(strstr(logs[0], "PROPERTY") != NULL);
    }
    
    for (int i = 0; i < count; i++) free(logs[i]);
    free(logs);
    
    database_close(db);
    cleanup_db(db_path);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_audit_log_basic);
    return UNITY_END();
}