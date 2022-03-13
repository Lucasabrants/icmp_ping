/**
 * @file icmp.hpp
 * @author Lucas Abrantes (lucasabrantesmarques@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2022-03-12
 * 
 * 
 */
#include <vector>
#include <memory>

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
    IcmpType type;
    unsigned char code;
    unsigned short checksum;
    std::vector<unsigned char> rest_of_message;

    void checksum_calc();

public:
    Icmp(IcmpType type, unsigned char code = 0);
    std::vector<unsigned char> encode();
    void set_last_parameters(std::unique_ptr<std::vector<unsigned char>> p_message);
};