#include "common.h"
#include "user.h"
#include "property.h"
#include "menu.h"
#include "database.h"

int main(void) {
    srand((unsigned int)time(NULL));
    
    Database *db = database_open("data/property_manage.db");
    if (!db) {
        fprintf(stderr, "Failed to open database\n");
        return 1;
    }
    
    if (!database_init_schema(db)) {
        fprintf(stderr, "Failed to initialize database schema\n");
        database_close(db);
        return 1;
    }
    
    database_migrate_from_files(db, USERS_FILE, PROPERTIES_FILE);
    
    menu_entry(db);
    
    database_close(db);
    
    return 0;
}