#include <stdio.h>
#include <string.h>
#include <unistd.h>

unsigned long hash(char *buff) {
    unsigned int uVar1;
    size_t sVar2;
    unsigned int local_14;
    size_t local_10;

    local_10 = 0;
    local_14 = 0;
    sVar2 = strlen(buff);
    for (; local_10 != sVar2; local_10 = local_10 + 1) {
        uVar1 = (local_14 + (int)buff[local_10]) * 0x401;
        local_14 = uVar1 ^ uVar1 >> 6 ^ (int)buff[local_10];
    }

    return local_14;
}


int main(void) {
    int sizeToRead = 8;
    char buff[sizeToRead];
    memset(buff, 0, sizeof(buff));
    read(STDIN_FILENO, buff, sizeToRead);
    unsigned long hash_result = hash(buff);

    // check result against known value
    if (hash_result == 0x03319f75) {
        printf("SUCCESS\n");
    } else {
        printf("FAIL\n");
    }
    
    return 0;
}