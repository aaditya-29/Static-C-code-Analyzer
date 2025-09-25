#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 256

void safe_function()
{
    char buffer[BUFFER_SIZE];
    char destination[BUFFER_SIZE];

    // Safe: fgets with size limit
    fgets(buffer, sizeof(buffer), stdin);

    // Safe: strncpy with size limit
    strncpy(destination, buffer, sizeof(destination) - 1);
    destination[sizeof(destination) - 1] = '\0';

    // Safe: strncat with remaining space calculation
    size_t remaining = sizeof(destination) - strlen(destination) - 1;
    strncat(destination, "suffix", remaining);

    // Safe: snprintf with buffer size
    snprintf(buffer, sizeof(buffer), "User input: %s", destination);

    // Safe: scanf with width specifier
    scanf("%255s", buffer);

    // Safe: avoid system() calls, use safer alternatives
    // system(buffer); // DON'T DO THIS

    // Better approach would be to validate input and use execve
}

int main()
{
    char buffer[BUFFER_SIZE];

    // Safe: literal format string
    printf("Enter some text: ");

    // Safe: proper input handling
    if (fgets(buffer, sizeof(buffer), stdin) != NULL)
    {
        // Remove newline if present
        buffer[strcspn(buffer, "\n")] = '\0';
        printf("You entered: %s\n", buffer);
    }

    safe_function();
    return 0;
}
