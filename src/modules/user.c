#include "user.h"
#include "sha256.h"
#include "common.h"
#include "property.h"
#include "ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <conio.h>
#include <windows.h>

static void ensure_data_dir(void) {
    MKDIR("data");
}

static int ensure_capacity(UserManager *um) {
    if (um->count >= um->capacity) {
        int new_capacity = um->capacity == 0 ? 100 : um->capacity * 2;
        User *new_users = realloc(um->users, new_capacity * sizeof(User));
        if (!new_users) return 0;
        um->users = new_users;
        um->capacity = new_capacity;
    }
    return 1;
}

UserManager *user_manager_create(const char *users_file, const char *salts_file) {
    ensure_data_dir();
    
    UserManager *um = malloc(sizeof(UserManager));
    if (!um) return NULL;
    um->users = NULL;
    um->count = 0;
    um->capacity = 0;
    strncpy(um->users_file, users_file, sizeof(um->users_file) - 1);
    strncpy(um->salts_file, salts_file, sizeof(um->salts_file) - 1);
    um->users_file[sizeof(um->users_file) - 1] = '\0';
    um->salts_file[sizeof(um->salts_file) - 1] = '\0';
    return um;
}

void user_manager_destroy(UserManager *um) {
    if (um) {
        free(um->users);
        free(um);
    }
}

static void user_serialize(const User *user, FILE *fp) {
    fprintf(fp, "%s|%s|%s|%s|%s|%s|%s|%s\n",
        user->username,
        user->first_name,
        user->last_name,
        user->id,
        user->phone,
        user->email,
        user->password_hash,
        user->salt
    );
}

static int user_deserialize(User *user, FILE *fp) {
    char line[2048];
    if (!fgets(line, sizeof(line), fp)) return 0;
    trim_newline(line);
    
    char *tokens[8];
    int token_count = 0;
    char *token = strtok(line, "|");
    while (token && token_count < 8) {
        tokens[token_count++] = token;
        token = strtok(NULL, "|");
    }
    
    if (token_count < 8) return 0;
    
    int idx = 0;
    strncpy(user->username, tokens[idx++], MAX_FIELD_LEN - 1);
    strncpy(user->first_name, tokens[idx++], MAX_FIELD_LEN - 1);
    strncpy(user->last_name, tokens[idx++], MAX_FIELD_LEN - 1);
    strncpy(user->id, tokens[idx++], MAX_FIELD_LEN - 1);
    strncpy(user->phone, tokens[idx++], MAX_FIELD_LEN - 1);
    strncpy(user->email, tokens[idx++], MAX_FIELD_LEN - 1);
    strncpy(user->password_hash, tokens[idx++], SHA256_DIGEST_LENGTH * 2);
    strncpy(user->salt, tokens[idx++], SALT_LENGTH);
    
    return 1;
}

int user_manager_load(UserManager *um) {
    FILE *fp = fopen(um->users_file, "r");
    if (!fp) return 0;
    
    User user;
    while (user_deserialize(&user, fp)) {
        if (!ensure_capacity(um)) {
            fclose(fp);
            return 0;
        }
        um->users[um->count++] = user;
    }
    
    fclose(fp);
    return 1;
}

int user_manager_save(UserManager *um) {
    FILE *fp = fopen(um->users_file, "w");
    if (!fp) return 0;
    
    for (int i = 0; i < um->count; i++) {
        user_serialize(&um->users[i], fp);
    }
    
    fclose(fp);
    return 1;
}

int user_manager_add(UserManager *um, const User *user) {
    if (!ensure_capacity(um)) return 0;
    
    if (user_manager_find_by_username(um, user->username)) return 0;
    
    um->users[um->count++] = *user;
    return user_manager_save(um);
}

User *user_manager_find_by_username(UserManager *um, const char *username) {
    for (int i = 0; i < um->count; i++) {
        if (strcmp(um->users[i].username, username) == 0) {
            return &um->users[i];
        }
    }
    return NULL;
}

int user_manager_update_password(UserManager *um, const char *username, const char *new_hash, const char *new_salt) {
    for (int i = 0; i < um->count; i++) {
        if (strcmp(um->users[i].username, username) == 0) {
            strncpy(um->users[i].password_hash, new_hash, SHA256_DIGEST_LENGTH * 2);
            strncpy(um->users[i].salt, new_salt, SALT_LENGTH);
            return user_manager_save(um);
        }
    }
    return 0;
}

int user_manager_update_field(UserManager *um, const char *username, int field, const char *value) {
    for (int i = 0; i < um->count; i++) {
        if (strcmp(um->users[i].username, username) == 0) {
            switch (field) {
                case USER_FIELD_FIRST_NAME:
                    strncpy(um->users[i].first_name, value, MAX_FIELD_LEN - 1);
                    break;
                case USER_FIELD_LAST_NAME:
                    strncpy(um->users[i].last_name, value, MAX_FIELD_LEN - 1);
                    break;
                case USER_FIELD_ID:
                    strncpy(um->users[i].id, value, MAX_FIELD_LEN - 1);
                    break;
                case USER_FIELD_PHONE:
                    strncpy(um->users[i].phone, value, MAX_FIELD_LEN - 1);
                    break;
                case USER_FIELD_EMAIL:
                    strncpy(um->users[i].email, value, MAX_FIELD_LEN - 1);
                    break;
                default:
                    return 0;
            }
            return user_manager_save(um);
        }
    }
    return 0;
}

void user_manager_list_all(UserManager *um) {
    for (int i = 0; i < um->count; i++) {
        printf("%s | %s %s | %s | %s\n", 
            um->users[i].username,
            um->users[i].first_name,
            um->users[i].last_name,
            um->users[i].phone,
            um->users[i].email
        );
    }
}

int validate_username(const char *username) {
    size_t len = strlen(username);
    if (len < 8 || len > 16) return 0;
    for (size_t i = 0; i < len; i++) {
        if (username[i] == ' ') return 0;
        if (!isalnum((unsigned char)username[i])) return 0;
    }
    return 1;
}

int validate_name(const char *name) {
    size_t len = strlen(name);
    if (len < 1 || len > 49) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isalpha((unsigned char)name[i]) && name[i] != ' ') return 0;
    }
    return 1;
}

int username_exists(UserManager *um, const char *username) {
    return user_manager_find_by_username(um, username) != NULL;
}

void get_password_hidden(char *buffer, int maxlen) {
    int i = 0;
    int ch;
    while (1) {
        ch = _getch();
        if (ch == '\r' || ch == '\n') {
            break;
        } else if (ch == '\b' || ch == 127) {
            if (i > 0) {
                i--;
                printf("\b \b");
            }
        } else if (i < maxlen - 1 && ch >= 32 && ch <= 126) {
            buffer[i++] = ch;
            printf("*");
        }
    }
    buffer[i] = '\0';
    printf("\n");
}

int user_register(UserManager *um) {
    ui_init();
    ui_clear();
    ui_header("SIGN UP", "Create your account");
    
    User new_user = {0};
    char input[MAX_FIELD_LEN];
    char pass1[MAX_FIELD_LEN], pass2[MAX_FIELD_LEN];
    char salt[SALT_LENGTH + 1];
    char hash[SHA256_DIGEST_LENGTH * 2 + 1];
    
    ui_form_start("ACCOUNT DETAILS");
    
    while (1) {
        if (!ui_form_field("Username", input, MAX_FIELD_LEN, validate_username, "8-16 chars, alphanumeric")) return 0;
        if (strcasecmp(input, "Admin") == 0) {
            ui_toast(UI_STYLE_WARNING, "Username 'Admin' is reserved");
            continue;
        }
        if (username_exists(um, input)) {
            ui_toast(UI_STYLE_ERROR, "Username already exists");
            continue;
        }
        strncpy(new_user.username, input, MAX_FIELD_LEN - 1);
        break;
    }
    
    while (1) {
        if (!ui_form_field("First Name", input, MAX_FIELD_LEN, validate_name, "Letters and spaces only")) return 0;
        capitalize_words(input);
        strncpy(new_user.first_name, input, MAX_FIELD_LEN - 1);
        break;
    }
    
    while (1) {
        if (!ui_form_field("Last Name", input, MAX_FIELD_LEN, validate_name, "Letters and spaces only")) return 0;
        capitalize_words(input);
        strncpy(new_user.last_name, input, MAX_FIELD_LEN - 1);
        break;
    }
    
    while (1) {
        if (!ui_form_field("National ID", input, MAX_FIELD_LEN, validate_id, "10 digits")) return 0;
        strncpy(new_user.id, input, MAX_FIELD_LEN - 1);
        break;
    }
    
    while (1) {
        if (!ui_form_field("Phone", input, MAX_FIELD_LEN, validate_phone, "09xxxxxxxxx")) return 0;
        strncpy(new_user.phone, input, MAX_FIELD_LEN - 1);
        break;
    }
    
    while (1) {
        if (!ui_form_field("Email", input, MAX_FIELD_LEN, validate_email, "user@domain.com")) return 0;
        strncpy(new_user.email, input, MAX_FIELD_LEN - 1);
        break;
    }
    
    ui_form_end();
    
    ui_form_start("SECURITY");
    while (1) {
        if (!ui_form_field_password("Password", pass1, MAX_FIELD_LEN, "Min 8 chars, upper, lower, digit")) return 0;
        if (!validate_password(pass1)) {
            ui_toast(UI_STYLE_ERROR, "Password does not meet requirements");
            continue;
        }
        
        if (!ui_form_field_password("Confirm Password", pass2, MAX_FIELD_LEN, "Must match above")) return 0;
        
        if (strcmp(pass1, pass2) != 0) {
            ui_toast(UI_STYLE_ERROR, "Passwords do not match");
            continue;
        }
        
        generate_salt(salt, SALT_LENGTH);
        hash_password(pass1, salt, hash);
        
        strncpy(new_user.password_hash, hash, SHA256_DIGEST_LENGTH * 2);
        strncpy(new_user.salt, salt, SALT_LENGTH);
        break;
    }
    ui_form_end();
    
    ui_spinner_start("Creating account...");
    Sleep(500);
    bool success = user_manager_add(um, &new_user);
    ui_spinner_stop();
    
    if (success) {
        ui_alert(UI_STYLE_SUCCESS, "Success", "Registration successful! Welcome to Property Management System.");
        return 1;
    } else {
        ui_alert(UI_STYLE_ERROR, "Error", "Registration failed. Please try again.");
        return 0;
    }
}

int user_login(UserManager *um, char *logged_in_username) {
    ui_init();
    ui_clear();
    ui_header("LOGIN", "Sign in to your account");
    
    char username[MAX_FIELD_LEN];
    char password[MAX_FIELD_LEN];
    char captcha[50];
    int expected, answer;
    
    ui_form_start("CREDENTIALS");
    if (!ui_form_field("Username", username, MAX_FIELD_LEN, NULL, "Your username")) return 0;
    if (!ui_form_field_password("Password", password, MAX_FIELD_LEN, "Your password")) return 0;
    ui_form_end();
    
    if (!validate_password(password)) {
        ui_alert(UI_STYLE_ERROR, "Error", "Invalid password format");
        return 0;
    }
    
    User *user = user_manager_find_by_username(um, username);
    if (!user) {
        ui_alert(UI_STYLE_ERROR, "Error", "User not found");
        return 0;
    }
    
    char computed_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    hash_password(password, user->salt, computed_hash);
    
    if (strcmp(computed_hash, user->password_hash) != 0) {
        if (strcmp(username, "Admin") == 0 && strcmp(password, "Admin1234") == 0) {
            strcpy(logged_in_username, "Admin");
            ui_alert(UI_STYLE_SUCCESS, "Admin Login", "Welcome, Administrator!");
            return 2;
        }
        ui_alert(UI_STYLE_ERROR, "Error", "Invalid password");
        return 0;
    }
    
    ui_form_start("SECURITY CHECK");
    while (1) {
        int num1 = rand() % 10 + 1;
        int num2 = rand() % 10 + 1;
        char ops[] = {'+', '-', '*'};
        char op = ops[rand() % 3];
        
        sprintf(captcha, "%d %c %d", num1, op, num2);
        switch (op) {
            case '+': expected = num1 + num2; break;
            case '-': expected = num1 - num2; break;
            case '*': expected = num1 * num2; break;
        }
        
        char ans_str[20];
        if (!ui_form_field("Captcha", ans_str, sizeof(ans_str), NULL, captcha)) continue;
        answer = atoi(ans_str);
        
        if (answer == expected) {
            ui_toast(UI_STYLE_SUCCESS, "Correct! Verification passed.");
            break;
        } else {
            ui_toast(UI_STYLE_ERROR, "Incorrect. Please try again.");
        }
    }
    ui_form_end();
    
    strcpy(logged_in_username, username);
    ui_alert(UI_STYLE_SUCCESS, "Welcome", "Login successful!");
    ui_print_styled(UI_STYLE_INFO, "  Hello, %s %s\n", user->first_name, user->last_name);
    Sleep(1000);
    return 1;
}

int user_change_password(UserManager *um, const char *username) {
    ui_init();
    ui_clear();
    ui_header("CHANGE PASSWORD", "Update your password");
    
    char old_pass[MAX_FIELD_LEN];
    char new_pass1[MAX_FIELD_LEN];
    char new_pass2[MAX_FIELD_LEN];
    char salt[SALT_LENGTH + 1];
    char hash[SHA256_DIGEST_LENGTH * 2 + 1];
    
    User *user = user_manager_find_by_username(um, username);
    if (!user) return 0;
    
    ui_form_start("VERIFICATION");
    if (!ui_form_field_password("Current Password", old_pass, MAX_FIELD_LEN, "Enter current password")) return 0;
    ui_form_end();
    
    char computed_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    hash_password(old_pass, user->salt, computed_hash);
    
    if (strcmp(computed_hash, user->password_hash) != 0) {
        ui_alert(UI_STYLE_ERROR, "Error", "Current password is incorrect");
        return 0;
    }
    
    ui_form_start("NEW PASSWORD");
    while (1) {
        if (!ui_form_field_password("New Password", new_pass1, MAX_FIELD_LEN, "Min 8 chars, upper, lower, digit")) return 0;
        if (!validate_password(new_pass1)) {
            ui_toast(UI_STYLE_ERROR, "Password does not meet requirements");
            continue;
        }
        
        if (!ui_form_field_password("Confirm New Password", new_pass2, MAX_FIELD_LEN, "Must match above")) return 0;
        
        if (strcmp(new_pass1, new_pass2) != 0) {
            ui_toast(UI_STYLE_ERROR, "Passwords do not match");
            continue;
        }
        
        generate_salt(salt, SALT_LENGTH);
        hash_password(new_pass1, salt, hash);
        
        ui_spinner_start("Updating password...");
        Sleep(500);
        bool success = user_manager_update_password(um, username, hash, salt);
        ui_spinner_stop();
        
        if (success) {
            ui_alert(UI_STYLE_SUCCESS, "Success", "Password changed successfully!");
            return 1;
        } else {
            ui_alert(UI_STYLE_ERROR, "Error", "Failed to update password");
            return 0;
        }
    }
}

int user_edit_profile(UserManager *um, const char *username) {
    ui_init();
    
    User *user = user_manager_find_by_username(um, username);
    if (!user) return 0;
    
    char input[MAX_FIELD_LEN];
    int choice;
    
    while (1) {
        ui_clear();
        ui_header("EDIT PROFILE", "Manage your account information");
        ui_status_bar(username, "SETTINGS", "");
        
        ui_print_styled(UI_STYLE_PRIMARY, "  Current Information:\n");
        ui_print_styled(UI_STYLE_DEFAULT, "  1. First Name: %s\n", user->first_name);
        ui_print_styled(UI_STYLE_DEFAULT, "  2. Last Name:  %s\n", user->last_name);
        ui_print_styled(UI_STYLE_DEFAULT, "  3. ID:         %s\n", user->id);
        ui_print_styled(UI_STYLE_DEFAULT, "  4. Phone:      %s\n", user->phone);
        ui_print_styled(UI_STYLE_DEFAULT, "  5. Email:      %s\n", user->email);
        printf("\n");
        
        ui_print_styled(UI_STYLE_INFO, "  6. Change Password\n");
        ui_print_styled(UI_STYLE_MUTED, "  0. Back\n");
        printf("\n");
        
        if (!ui_form_field_int("Select option", &choice, 0, 6, "0-6")) continue;
        
        if (choice == 0) break;
        if (choice == 6) {
            user_change_password(um, username);
            user = user_manager_find_by_username(um, username); // Refresh
            continue;
        }
        
        const char *prompts[] = {"", "First Name", "Last Name", "ID (10 digits)", "Phone (09xxxxxxxxx)", "Email"};
        int (*validators[])(const char *) = {NULL, validate_name, validate_name, validate_id, validate_phone, validate_email};
        void (*formatters[])(char *) = {NULL, capitalize_words, capitalize_words, NULL, NULL, NULL};
        
        if (!ui_form_field(prompts[choice], input, MAX_FIELD_LEN, validators[choice], "Enter new value")) continue;
        if (formatters[choice]) formatters[choice](input);
        
        ui_spinner_start("Saving...");
        Sleep(300);
        if (user_manager_update_field(um, username, choice, input)) {
            ui_spinner_stop();
            ui_alert(UI_STYLE_SUCCESS, "Success", "Profile updated successfully!");
            user = user_manager_find_by_username(um, username); // Refresh
        } else {
            ui_spinner_stop();
            ui_alert(UI_STYLE_ERROR, "Error", "Update failed!");
        }
    }
    return 1;
}