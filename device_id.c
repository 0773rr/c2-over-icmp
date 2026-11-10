#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

int main(){
    const char *paths[] = {
        "/etc/machine-id",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor"
    };

    uint64_t id = UINT64_C(14695981039346656037);

    for (int i = 0; i < 3; i++) {
        FILE *f = fopen(paths[i], "r");

        int character;
        while ((character = fgetc(f)) != EOF) {
            if (character == '\n' || character == '\r')
                continue;

            id ^= (unsigned char)character;
            id *= UINT64_C(1099511628211);
        }

        fclose(f);

        id ^= 255;
        id *= UINT64_C(1099511628211);
    }

    return 0;
}
