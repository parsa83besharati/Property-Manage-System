#include "common.h"
#include "user.h"
#include "property.h"
#include "menu.h"
#include "database.h"
#include "config.h"

int main(void) {
    srand((unsigned int)time(NULL));
    
    Config config;
    config_load("config.ini", &config);
    
    Database *db = database_open(config.db_path);
    if (!db) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }
    
    if (!database_init_schema(db)) {
        fprintf(stderr, "Failed to initialize database schema\n");
        database_close(db);
        return 1;
    }
    
    database_migrate_from_files(db, config.users_file, config.properties_file);
    
    menu_entry(db);
    
    database_close(db);
    
    return 0;
}