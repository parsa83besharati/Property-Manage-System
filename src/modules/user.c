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

int user_register(Database *db) {
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
        if (username_exists(db, input)) {
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
    bool success = db_user_create(db, &new_user);
    ui_spinner_stop();
    
    if (success) {
        ui_alert(UI_STYLE_SUCCESS, "Success", "Registration successful! Welcome to Property Management System.");
        return 1;
    } else {
        ui_alert(UI_STYLE_ERROR, "Error", "Registration failed. Please try again.");
        return 0;
    }
}

int user_login(Database *db, char *logged_in_username) {
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
    
    User *user = db_user_find_by_username(db, username);
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
            free(user);
            return 2;
        }
        ui_alert(UI_STYLE_ERROR, "Error", "Invalid password");
        free(user);
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
    free(user);
    return 1;
}

int user_change_password(Database *db, const char *username) {
    ui_init();
    ui_clear();
    ui_header("CHANGE PASSWORD", "Update your password");
    
    char old_pass[MAX_FIELD_LEN];
    char new_pass1[MAX_FIELD_LEN];
    char new_pass2[MAX_FIELD_LEN];
    char salt[SALT_LENGTH + 1];
    char hash[SHA256_DIGEST_LENGTH * 2 + 1];
    
    User *user = db_user_find_by_username(db, username);
    if (!user) return 0;
    
    ui_form_start("VERIFICATION");
    if (!ui_form_field_password("Current Password", old_pass, MAX_FIELD_LEN, "Enter current password")) {
        free(user);
        return 0;
    }
    ui_form_end();
    
    char computed_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    hash_password(old_pass, user->salt, computed_hash);
    
    if (strcmp(computed_hash, user->password_hash) != 0) {
        ui_alert(UI_STYLE_ERROR, "Error", "Current password is incorrect");
        free(user);
        return 0;
    }
    
    ui_form_start("NEW PASSWORD");
    while (1) {
        if (!ui_form_field_password("New Password", new_pass1, MAX_FIELD_LEN, "Min 8 chars, upper, lower, digit")) {
            free(user);
            return 0;
        }
        if (!validate_password(new_pass1)) {
            ui_toast(UI_STYLE_ERROR, "Password does not meet requirements");
            continue;
        }
        
        if (!ui_form_field_password("Confirm New Password", new_pass2, MAX_FIELD_LEN, "Must match above")) {
            free(user);
            return 0;
        }
        
        if (strcmp(new_pass1, new_pass2) != 0) {
            ui_toast(UI_STYLE_ERROR, "Passwords do not match");
            continue;
        }
        
        generate_salt(salt, SALT_LENGTH);
        hash_password(new_pass1, salt, hash);
        
        ui_spinner_start("Updating password...");
        Sleep(500);
        bool success = db_user_update_password(db, username, hash, salt);
        ui_spinner_stop();
        
        free(user);
        if (success) {
            ui_alert(UI_STYLE_SUCCESS, "Success", "Password changed successfully!");
            return 1;
        } else {
            ui_alert(UI_STYLE_ERROR, "Error", "Failed to update password");
            return 0;
        }
    }
}

int user_edit_profile(Database *db, const char *username) {
    ui_init();
    
    User *user = db_user_find_by_username(db, username);
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
            user_change_password(db, username);
            free(user);
            user = db_user_find_by_username(db, username);
            continue;
        }
        
        const char *prompts[] = {"", "First Name", "Last Name", "ID (10 digits)", "Phone (09xxxxxxxxx)", "Email"};
        int (*validators[])(const char *) = {NULL, validate_name, validate_name, validate_id, validate_phone, validate_email};
        void (*formatters[])(char *) = {NULL, capitalize_words, capitalize_words, NULL, NULL, NULL};
        
        if (!ui_form_field(prompts[choice], input, MAX_FIELD_LEN, validators[choice], "Enter new value")) continue;
        if (formatters[choice]) formatters[choice](input);
        
        ui_spinner_start("Saving...");
        Sleep(300);
        if (db_user_update_field(db, username, choice, input)) {
            ui_spinner_stop();
            ui_alert(UI_STYLE_SUCCESS, "Success", "Profile updated successfully!");
            free(user);
            user = db_user_find_by_username(db, username);
        } else {
            ui_spinner_stop();
            ui_alert(UI_STYLE_ERROR, "Error", "Update failed!");
        }
    }
    free(user);
    return 1;
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

int username_exists(Database *db, const char *username) {
    User *user = db_user_find_by_username(db, username);
    if (user) {
        free(user);
        return 1;
    }
    return 0;
}