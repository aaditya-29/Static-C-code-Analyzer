#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function() {
    char buffer[10];
    char *user_input;
    char destination[20];
    
    // Dangerous: gets() can cause buffer overflow
    gets(buffer);
    
    // Dangerous: strcpy without bounds checking
    strcpy(destination, buffer);
    
    // Dangerous: strcat without bounds checking  
    strcat(destination, "suffix");
    
    // Dangerous: sprintf can overflow
    sprintf(buffer, "User input: %s", user_input);
    
    // Dangerous: scanf %s without width specifier
    scanf("%s", buffer);
    
    // Very dangerous: system() call with user input
    system(buffer);
    
    // Dangerous: popen with potential user input
    popen("ls -la", "r");
    
    // Dangerous: exec function
    execl("/bin/sh", "sh", "-c", buffer, NULL);
}

int main() {
    char cmd[100];
    char format_string[50];
    
    // Format string vulnerability
    printf(format_string);
    
    // Another dangerous system call
    system(cmd);
    
    vulnerable_function();
    return 0;
}
