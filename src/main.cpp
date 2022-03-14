/**
 * @file main.cpp
 * @author Lucas Abrantes (lucasabrantesmarques@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2022-03-12
 * 
 * 
 */

#include <iostream>
#include <chrono>
#include <string>
#include <ctime>
#include <array>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include "icmp.hpp"

using namespace std::chrono;

#define PING_PORT_NUMBER 0
#define PING_SLEEP_RATE 1000000
#define RECEIVE_TIMEOUT 1
#define MAX_DATA_SIZE 56
#define MAX_SIZE_MESSAGE 84
#define SEQUENCE_NUMBER_INDEX 2

int ping_rum = 1;

nanoseconds get_uptime()
{
    timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    {
        return duration_cast<nanoseconds>(seconds(ts.tv_sec) + nanoseconds(ts.tv_nsec));
    }
    else
    {
        return duration_cast<nanoseconds>(nanoseconds(0));
    }
}

std::string dns_resolv_to_ip(const char *address_host, struct sockaddr_in *internet_socket_address)
{
    std::cout << "\nResolvendo DNS\n";
    struct hostent *host_entry;
    std::string ip;

    host_entry = gethostbyname(address_host);
    if (host_entry == NULL)
    {
        return ip;
    }

    ip = inet_ntoa(*(struct in_addr *)host_entry->h_addr);

    internet_socket_address->sin_family = host_entry->h_addrtype;
    internet_socket_address->sin_port = htons(PING_PORT_NUMBER);
    internet_socket_address->sin_addr.s_addr = *(long *)host_entry->h_addr;

    return ip;
}

std::string dns_resolv_to_host_name(const char *ip_address)
{
    char aux_buffer[NI_MAXHOST];
    std::string host_name;
    struct sockaddr_in internet_socket_address;

    internet_socket_address.sin_family = AF_INET;
    internet_socket_address.sin_addr.s_addr = inet_addr(ip_address);

    if (getnameinfo((struct sockaddr *)&internet_socket_address, sizeof(struct sockaddr_in),
                    aux_buffer, sizeof(aux_buffer), NULL, 0, NI_NAMEREQD))
    {
        std::cout << "\n Erro ao encontrar o host name a partir do endereço ip.\n";
        return host_name;
    }

    host_name = aux_buffer;
    return host_name;
}

int connet_socket()
{
    int socket_fd;
    if (getuid())
    {
        socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    }
    else
    {
        socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }

    return socket_fd;
}

void signal_handler(int signal)
{
    ping_rum = 0;
}

void rum_ping_command(int socket_fd, struct sockaddr_in *internet_socket_address_send, const char *host_name,
                      const char *ip_address, const char *src_address)
{
    std::vector<unsigned char> rest_of_message_send, message;
    std::array<unsigned char, MAX_SIZE_MESSAGE> receive_message;
    Icmp icmp(IcmpType::ECHO_REQUEST);
    struct sockaddr_in internet_socket_address_receive;
    unsigned int internet_socket_address_receive_len, ttl_send = 255;
    nanoseconds time_send, time_receive, time_begin, time_end;
    struct timeval time_out_to_receive = {.tv_sec = RECEIVE_TIMEOUT, .tv_usec = 0};
    unsigned short identifier = getpid();
    unsigned short sequence_number = 0;
    unsigned char ttl_receive;

    icmp.set_source_address("192.168.100.105");
    icmp.set_destination_address(ip_address);
    rest_of_message_send.push_back(static_cast<unsigned char>((identifier >> 8) & 0xFF));
    rest_of_message_send.push_back(static_cast<unsigned char>(identifier & 0xFF));
    rest_of_message_send.insert(rest_of_message_send.end(), 2, 0);
    rest_of_message_send.insert(rest_of_message_send.end(), MAX_DATA_SIZE, 0xFF);

    if (setsockopt(socket_fd, IPPROTO_IP, IP_TTL, &ttl_send, sizeof(ttl_send)) != 0)
    {
        std::cout << "\nSetting socket options to TTL failed!\n";
        return;
    }
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&time_out_to_receive, sizeof(struct timeval));

    std::cout << "PING " << src_address << " (" << ip_address << ") " << MAX_DATA_SIZE << "(" << MAX_SIZE_MESSAGE << ") bytes of data.\n";
    while (ping_rum)
    {
        usleep(PING_SLEEP_RATE);
        sequence_number++;
        rest_of_message_send.at(SEQUENCE_NUMBER_INDEX) = static_cast<unsigned char>((sequence_number >> 8) & 0xFF);
        rest_of_message_send.at(SEQUENCE_NUMBER_INDEX + 1) = static_cast<unsigned char>(sequence_number & 0xFF);

        icmp.set_last_parameters(rest_of_message_send);

        time_send = get_uptime();
        if (sendto(socket_fd, icmp.encode().data(), MAX_SIZE_MESSAGE, 0, 
            (struct sockaddr *)internet_socket_address_send, sizeof(struct sockaddr)) <= 0)
        {
            std::cout << "\nErro ao enviar mensagem via socket!\n";
            continue;
        }

        internet_socket_address_receive_len = sizeof(internet_socket_address_receive);
        if (recvfrom(socket_fd, receive_message.data(), receive_message.size(), 0,
            (struct sockaddr *)&internet_socket_address_receive, &internet_socket_address_receive_len) <= 0)
        {
            std::cout << "\nErro ao receber mensagem via socket!\n";
        }
        else
        {
            time_receive = get_uptime();
            message.clear();
            message.insert(message.begin(), receive_message.data(), receive_message.data() + MAX_SIZE_MESSAGE);
            icmp.decode(message, &ttl_receive, nullptr, nullptr, nullptr);

            std::cout << ICMP_PING_SIZE << " bytes de " << host_name << " (" << ip_address << "): icmp_seq=" << sequence_number << 
                      " ttl=" << int(ttl_receive) << " tempo=" << (duration_cast<milliseconds>(time_receive - time_send).count()) << "ms\n";
        }
    }
    
}

int main(int argc, char *argv[])
{
    int socket_fd;
    std::string ip_address, host_name;
    struct sockaddr_in internet_socket_address;

    if (argc < 2 || argc > 4)
    {
        std::cout << "\nNumero de parametros invalido.\n";
        return 0;
    }

    ip_address = dns_resolv_to_ip(argv[1], &internet_socket_address);

    std::cout << "Ip " << ip_address << std::endl;

    host_name = dns_resolv_to_host_name(ip_address.c_str());

    std::cout << "Host name " << host_name << std::endl;

    socket_fd = connet_socket();
    if (socket_fd < 0)
    {
        std::cout << "\nErro ao abrir o socket!\n";
        return 0;
    }

    signal(SIGINT, signal_handler);

    rum_ping_command(socket_fd, &internet_socket_address, host_name.c_str(), ip_address.c_str(),
                     argv[1]);

    return 0;
}
