/**
 * @file icmp.hpp
 * @author Lucas Abrantes (lucasabrantesmarques@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2022-03-12
 * 
 * 
 */

#ifndef __ICMP_HPP__
#define __ICMP_HPP__

#include <vector>
#include <memory>

#define ICMP_PING_SIZE 64 //Tamanho em bytes

// Tipos de mensagens difinidas na referencia do protocolo ICMP
enum class IcmpType : unsigned char
{
    ECHO_REPLY,
    DESTINATION_UNREACHABLE = 3,
    SOURCE_QUENCH,
    REDIRECT_MESSAGE,
    ECHO_REQUEST = 8,
    ROUTER_ADVERTISEMENT,
    ROUTER_SOLICITATION,
    TIME_EXCEEDED,
    PARAMETER_PROBLEM,
    TIMESTAMP,
    TIMESTAMP_REPLY,
    INFORMATION_REQUEST,
    INFORMATION_REPLY,
    ADDRESS_MASK_REQUEST,
    ADDRESS_MASK_REPLY,
    TRACEROUTE = 30,
    EXTENDED_ECHO_REQUEST = 42,
    EXTENDED_ECHO_REPLY,
};

class Icmp
{
private:
    unsigned char code;
    unsigned short checksum;
    IcmpType type;
    std::vector<unsigned char> rest_of_message;

    void checksum_calc();

public:
    Icmp();
    Icmp(IcmpType type, unsigned char code = 0);
    std::vector<unsigned char> encode();
    void decode(std::vector<unsigned char> &message, unsigned char * ttl, 
               unsigned int *source_address, unsigned int *destination_address,
               std::shared_ptr<std::vector<unsigned char>> rest_of_message);
    void set_last_parameters(std::vector<unsigned char> &p_message);
};

#endif // __ICMP_HPP__