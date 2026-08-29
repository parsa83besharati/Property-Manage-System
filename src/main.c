#include "common.h"
#include "user.h"
#include "property.h"
#include "menu.h"

int main(void) {
    srand((unsigned int)time(NULL));
    
    UserManager *um = user_manager_create(USERS_FILE, SALTS_FILE);
    if (!um) {
        fprintf(stderr, "Failed to create user manager\n");
        return 1;
    }
    
    PropertyManager *pm = property_manager_create(PROPERTIES_FILE);
    if (!pm) {
        fprintf(stderr, "Failed to create property manager\n");
        user_manager_destroy(um);
        return 1;
    }
    
    user_manager_load(um);
    property_manager_load(pm);
    
    menu_entry(um, pm);
    
    property_manager_save(pm);
    user_manager_save(um);
    
    property_manager_destroy(pm);
    user_manager_destroy(um);
    
    return 0;
}