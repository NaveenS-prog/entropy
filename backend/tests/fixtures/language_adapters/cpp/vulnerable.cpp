// TEST DATA FIXTURE - VULNERABLE C++ PATTERNS
#include <iostream>
#include <cstring>

struct Header {
    int id;
    char tag[4];
};

void process_request(const char* data) {
    // Unmanaged raw dynamic memory (ENT-CPP-001)
    int* raw_buffer = new int[100];
    delete raw_buffer;

    // Dangerous type punning (ENT-CPP-002)
    Header* header = reinterpret_cast<Header*>(raw_buffer);

    // Legacy unsafe C string functions in C++ (ENT-CPP-003)
    char local_buf[64];
    strcpy(local_buf, data);
    sprintf(local_buf, "Result: %s", data);
}
