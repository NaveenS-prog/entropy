/* TEST DATA FIXTURE - VULNERABLE C PATTERNS */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_data(char *input) {
    char buf[64];
    // Dangerous buffer and string operations (ENT-C-001)
    strcpy(buf, input);
    strcat(buf, "_suffix");
    sprintf(buf, "User input: %s", input);

    // Unsafe formatted input (ENT-C-002)
    char name[32];
    scanf("%s", name);

    // Dangerous command execution (ENT-C-003)
    char cmd[128];
    sprintf(cmd, "echo %s", input);
    system(cmd);
}
