/* TEST DATA FIXTURE - CLEAN C PATTERNS */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_process_data(const char *input) {
    char buf[64];
    // Safe bounded string operations
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    snprintf(buf, sizeof(buf), "User input: %s", input);

    // Safe bounded input handling
    char name[32];
    if (fgets(name, sizeof(name), stdin) != NULL) {
        printf("Hello, %s\n", name);
    }
}
