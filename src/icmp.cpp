/**
 * @file icmp.cpp
 * @author Lucas Abrantes (lucasabrantesmarques@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2022-03-12
 * 
 * 
 */

#include "icmp.hpp"
#include <iostream>
#include <arpa/inet.h>

#define ICMP_HEADER_SIZE 20
#define ICMP_VERSION 4
#define INTERNET_HEADER_LENGTH 5
#define ICMP_PING_SIZE 64 //tamanho em bytes
#define MAX_TTL_VALUE 255
#define ICMP_TTL_INDEX 8
#define ICMP_SOURCE_ADDRESS_INDEX 12
#define ICMP_DESTINATION_ADDRESS_INDEX 16
#define ICMP_REST_OF_MESSAGE_INDEX 24

std::vector<std::string> split(const std::string &str, char delimiter);

Icmp::Icmp()
{
    this->header_checksun = 0;
    this->checksum = 0;
    this->versio_and_ihl = (0x4 << ICMP_VERSION) | INTERNET_HEADER_LENGTH;
    this->type_of_service = 0;
    this->identification = 0;
    this->flags_and_fragment_offset = 0;
    this->ttl = MAX_TTL_VALUE;
    this->protocol = 1;
    this->source_address = 0;
    this->destination_address = 0;
}

Icmp::Icmp(IcmpType type, unsigned char code) : type(type),
                                                code(code)
{
    this->header_checksun = 0;
    this->checksum = 0;
    this->versio_and_ihl = (0x4 << ICMP_VERSION) | INTERNET_HEADER_LENGTH;
    this->type_of_service = 0;
    this->identification = 0;
    this->flags_and_fragment_offset = 0;
    this->ttl = MAX_TTL_VALUE;
    this->protocol = 1;
    this->source_address = 0;
    this->destination_address = 0;

    switch (this->type)
    {
        case IcmpType::ECHO_REQUEST:
        {
            this->total_length = ICMP_HEADER_SIZE + ICMP_PING_SIZE;
            this->rest_of_message = std::vector<unsigned char>((ICMP_PING_SIZE - 
                                                                sizeof(this->type)- 
                                                                sizeof(this->code)- 
                                                                sizeof(this->checksum)), 0);
            break;
        }
        //TODO: Implementar o restante das mensagens do protocolo ICMP
        default:
        {
            break;
        }
    }
}

void Icmp::set_last_parameters(std::vector<unsigned char> &message)
{
    if (message.size() > this->rest_of_message.size())
    {
        std::cout << "Tamanho da mensagem maior que o tamanho máximo do tipo definido, MAX_SIZE("
        << ICMP_PING_SIZE << ")\n";
        return;
    }

    for (int i = 0; i < message.size(); i++)
    {
        this->rest_of_message.at(i) = message.at(i);
    }
}

void Icmp::set_source_address(const std::string ipv4_address)
{
    std::vector<std::string> ip_numbers;
    struct sockaddr_in internet_socket_address;
    if (inet_pton(AF_INET, ipv4_address.c_str(), &(internet_socket_address.sin_addr)) == 0)
    {
        throw;
    }

    ip_numbers = split(ipv4_address, '.');

    this->source_address = (std::atoi(ip_numbers.at(0).c_str()) << 24) & 0xFF000000;
    this->source_address |= (std::atoi(ip_numbers.at(1).c_str()) << 16) & 0x00FF0000;
    this->source_address |= (std::atoi(ip_numbers.at(2).c_str()) << 8) & 0x0000FF00;
    this->source_address |= std::atoi(ip_numbers.at(3).c_str()) & 0x000000FF;
}

void Icmp::set_destination_address(const std::string ipv4_address)
{
    std::vector<std::string> ip_numbers;
    struct sockaddr_in internet_socket_address;
    if (inet_pton(AF_INET, ipv4_address.c_str(), &(internet_socket_address.sin_addr)) == 0)
    {
        throw;
    }

    ip_numbers = split(ipv4_address, '.');

    this->destination_address = (std::atoi(ip_numbers.at(0).c_str()) << 24) & 0xFF000000;
    this->destination_address |= (std::atoi(ip_numbers.at(1).c_str()) << 16) & 0x00FF0000;
    this->destination_address |= (std::atoi(ip_numbers.at(2).c_str()) << 8) & 0x0000FF00;
    this->destination_address |= std::atoi(ip_numbers.at(3).c_str()) & 0x000000FF;
}

std::vector<unsigned char> Icmp::encode()
{
    std::vector<unsigned char> message;
    this->checksum_calc();
    this->header_checksum_calc();

    message.push_back(this->versio_and_ihl);
    message.push_back(this->type_of_service);
    message.push_back(static_cast<unsigned char>((this->total_length >> 8) & 0xFF));
    message.push_back(static_cast<unsigned char>(this->total_length & 0xFF));
    message.push_back(static_cast<unsigned char>((this->identification >> 8) & 0xFF));
    message.push_back(static_cast<unsigned char>(this->identification & 0xFF));
    message.push_back(static_cast<unsigned char>((this->flags_and_fragment_offset >> 8) & 0xFF));
    message.push_back(static_cast<unsigned char>(this->flags_and_fragment_offset & 0xFF));
    message.push_back(this->ttl);
    message.push_back(this->protocol);
    
    message.push_back(static_cast<unsigned char>(this->header_checksun & 0xFF));
    message.push_back(static_cast<unsigned char>((this->header_checksun >> 8) & 0xFF));
    
    message.push_back(static_cast<unsigned char>((this->source_address >> 24) & 0xFF));
    message.push_back(static_cast<unsigned char>((this->source_address >> 16) & 0xFF));
    message.push_back(static_cast<unsigned char>((this->source_address >> 8) & 0xFF));
    message.push_back(static_cast<unsigned char>(this->source_address & 0xFF));
    message.push_back(static_cast<unsigned char>((this->destination_address >> 24) & 0xFF));
    message.push_back(static_cast<unsigned char>((this->destination_address >> 16) & 0xFF));
    message.push_back(static_cast<unsigned char>((this->destination_address >> 8) & 0xFF));
    message.push_back(static_cast<unsigned char>(this->destination_address & 0xFF));
    message.push_back(static_cast<unsigned char>(this->type));
    message.push_back(this->code);

    message.push_back(static_cast<unsigned char>(this->checksum & 0xFF));
    message.push_back(static_cast<unsigned char>((this->checksum >> 8) & 0xFF));
    
    message.insert(message.end(), this->rest_of_message.begin(), this->rest_of_message.end());

    return message;
}

void Icmp::decode(std::vector<unsigned char> &message, unsigned char * ttl, 
               unsigned int *source_address, unsigned int *destination_address,
               std::vector<unsigned char> &rest_of_message)
{
    if (message.empty())
    {
        throw;
    }

    if (ttl != nullptr)
    {
        *ttl = message.at(ICMP_TTL_INDEX);
    }

    if (source_address != nullptr)
    {
        *source_address = (message.at(ICMP_SOURCE_ADDRESS_INDEX) << 24) & 0xFF000000;
        *source_address |= (message.at(ICMP_SOURCE_ADDRESS_INDEX + 1) << 16) & 0x00FF0000;
        *source_address |= (message.at(ICMP_SOURCE_ADDRESS_INDEX + 2) << 8) & 0x0000FF00;
        *source_address |= message.at(ICMP_SOURCE_ADDRESS_INDEX + 3) & 0x000000FF;
    }

    if (destination_address != nullptr)
    {
        *destination_address = (message.at(ICMP_DESTINATION_ADDRESS_INDEX) << 24) & 0xFF000000;
        *destination_address |= (message.at(ICMP_DESTINATION_ADDRESS_INDEX + 1) << 16) & 0x00FF0000;
        *destination_address |= (message.at(ICMP_DESTINATION_ADDRESS_INDEX + 2) << 8) & 0x0000FF00;
        *destination_address |= message.at(ICMP_DESTINATION_ADDRESS_INDEX + 3) & 0x000000FF;
    }

    if (!rest_of_message.empty())
    {
        rest_of_message.clear();
        rest_of_message.insert(rest_of_message.begin(), message.begin() + ICMP_REST_OF_MESSAGE_INDEX, message.end());
    }
}

void Icmp::checksum_calc(const std::vector<unsigned char> &message)
{
    unsigned int sum = 0;
    unsigned short result;

    if (message.empty())
    {

        sum += ((this->code << 8) & 0xFF00) | static_cast<unsigned char>(this->type);
        
        for (auto it = this->rest_of_message.begin(); it < this->rest_of_message.end(); it += 2)
        {
            sum += (((*(it + 1)) << 8) & 0xFF00) | *(it);

            if ((it + 1) == this->rest_of_message.end())
            {
                break;
            }
        }
    }
    else
    {
        for (auto it = message.begin(); it < message.end(); it += 2)
        {
            sum += (((*(it + 1)) << 8) & 0xFF00) | *(it);

            if ((it + 1) == message.end())
            {
                break;
            }
        }  
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    this->checksum = result;
}

void Icmp::header_checksum_calc(const std::vector<unsigned char> &header_message)
{
    unsigned int sum = 0;
    unsigned short result;

    if (header_message.empty())
    {
        std::vector<unsigned char> aux_vector;

        aux_vector.push_back(this->versio_and_ihl);
        aux_vector.push_back(this->type_of_service);
        aux_vector.push_back(static_cast<unsigned char>((this->total_length >> 8) & 0xFF));
        aux_vector.push_back(static_cast<unsigned char>(this->total_length & 0xFF));
        aux_vector.push_back(static_cast<unsigned char>((this->identification >> 8) & 0xFF));
        aux_vector.push_back(static_cast<unsigned char>(this->identification & 0xFF));
        aux_vector.push_back(static_cast<unsigned char>((this->flags_and_fragment_offset >> 8) & 0xFF));
        aux_vector.push_back(static_cast<unsigned char>(this->flags_and_fragment_offset & 0xFF));
        aux_vector.push_back(this->ttl);
        aux_vector.push_back(this->protocol);
        aux_vector.push_back(static_cast<unsigned char>((this->source_address >> 24) & 0xFF));
        aux_vector.push_back(static_cast<unsigned char>((this->source_address >> 16) & 0xFF));
        aux_vector.push_back(static_cast<unsigned char>((this->source_address >> 8) & 0xFF));
        aux_vector.push_back(static_cast<unsigned char>(this->source_address & 0xFF));
        aux_vector.push_back(static_cast<unsigned char>((this->destination_address >> 24) & 0xFF));
        aux_vector.push_back(static_cast<unsigned char>((this->destination_address >> 16) & 0xFF));
        aux_vector.push_back(static_cast<unsigned char>((this->destination_address >> 8) & 0xFF));
        aux_vector.push_back(static_cast<unsigned char>(this->destination_address & 0xFF));
        
        for (auto it = aux_vector.begin(); it < aux_vector.end(); it += 2)
        {
            sum += (((*(it + 1)) << 8) & 0xFF00) | *(it);

            if ((it + 1) == aux_vector.end())
            {
                break;
            }
        }
    }
    else
    {
        for (auto it = header_message.begin(); it < header_message.end(); it += 2)
        {
            sum += (((*(it + 1)) << 8) & 0xFF00) | *(it);

            if ((it + 1) == header_message.end())
            {
                break;
            }
        }
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    this->header_checksun = result;
}

std::vector<std::string> split(const std::string &str, char delimiter)
{
    auto i = 0;
    std::vector<std::string> list;
 
    auto pos = str.find(delimiter);
 
    while (pos != std::string::npos)
    {
        list.push_back(str.substr(i, pos - i));
        i = ++pos;
        pos = str.find(delimiter, pos);
    }
 
    list.push_back(str.substr(i, str.length()));
 
    return list;
}