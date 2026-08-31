#include "database.h"
#include "user.h"
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(path) _mkdir(path)
#else
#include <sys/stat.h>
#define MKDIR(path) mkdir(path, 0755)
#endif

void cleanup_db(const char *path) {
    remove(path);
    char buf[300];
    snprintf(buf, sizeof(buf), "%s-shm", path); remove(buf);
    snprintf(buf, sizeof(buf), "%s-wal", path); remove(buf);
}

int main(void) {
    MKDIR("data");
    printf("data dir created\n");
    
    char db_path[100];
    sprintf(db_path, "data/test_debug_%d.db", rand());
    
    printf("Attempting to open: %s\n", db_path);
    Database *db = database_open(db_path);
    if (!db) {
        printf("Failed to open database\n");
        return 1;
    }
    printf("Database opened successfully\n");
    
    int r = database_init_schema(db);
    printf("Schema init: %d\n", r);
    
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
    int r2 = db_user_create(db, &u);
    printf("User create: %d\n", r2);
    if (r2 == 0) {
        // Try to find the user
        User *found = db_user_find_by_username(db, "testuser");
        if (found) {
            printf("User already exists: %s\n", found->username);
            free(found);
        } else {
            printf("User not found after failed create\n");
        }
    }
    
    database_close(db);
    cleanup_db(db_path);
    return 0;
}