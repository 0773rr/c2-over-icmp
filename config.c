#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

struct Config {
    struct in_addr c2_ip;
    unsigned int minimum_poll_seconds;
    unsigned int maximum_poll_seconds;
    int compression_level;
};

int main(void) {

    struct Config configuration = {
        .minimum_poll_seconds = 1,
        .maximum_poll_seconds = 3,
        .compression_level = 6
    };

    inet_pton(AF_INET, "192.168.67.20", &configuration.c2_ip);
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

    for (int i = configuration.minimum_poll_seconds; i <= configuration.maximum_poll_seconds; i++) {

        unsigned int delay_before_next_poll = configuration.minimum_poll_seconds + (int)rand() % (configuration.maximum_poll_seconds - configuration.minimum_poll_seconds + 1);
        sleep(delay_before_next_poll);

    }

    return 0;
}

