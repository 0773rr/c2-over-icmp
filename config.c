#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct Config {
    struct in_addr c2_ip;
    int poll_min;
    int poll_max;
    int compression_level;
};

int main(int argc, char *argv[])
{
    struct Config config;

    inet_pton(AF_INET, argv[1], &config.c2_ip);

    config.poll_min = atoi(argv[2]);
    config.poll_max = atoi(argv[3]);
    config.compression_level = atoi(argv[4]);

    return 0;
}
