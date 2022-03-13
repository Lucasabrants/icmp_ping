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

#define ICMP_PING_SIZE 64 //tamanho em bytes

Icmp::Icmp(IcmpType type, unsigned char code) : type(type),
                                                code(code)
{
    this->checksum = 0;

    switch (this->type)
    {
        case IcmpType::ECHO_REQUEST:
        {
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

void Icmp::set_last_parameters(std::unique_ptr<std::vector<unsigned char>> p_message)
{
    if (p_message.get()->size() > this->rest_of_message.size())
    {
        std::cout << "Tamanho da mensagem maior que o tamanho máximo do tipo definido, MAX_SIZE("
        << ICMP_PING_SIZE << ")\n";
        return;
    }

    for (int i = 0; i < p_message.get()->size(); i++)
    {
        this->rest_of_message.at(i) = p_message.get()->at(i);
    }
}

std::vector<unsigned char> Icmp::encode()
{
    std::vector<unsigned char> message;
    this->checksum_calc();

    message.push_back(static_cast<unsigned char>(this->type));
    message.push_back(this->code);
    message.push_back(static_cast<unsigned char>((this->checksum >> 8) & 0xFF));
    message.push_back(static_cast<unsigned char>(this->checksum & 0xFF));
    message.insert(message.end(), this->rest_of_message.begin(), this->rest_of_message.end());

    return message;
}

void Icmp::checksum_calc()
{
    unsigned int sum = 0;
    unsigned short result;
    std::vector<unsigned char>::iterator it = this->rest_of_message.begin();

    sum += ((static_cast<unsigned char>(this->code) << 8) & 0xFF00) | this->type;
    
    for (auto it = this->rest_of_message.begin(); it < this->rest_of_message.end(); it += 2)
    {
        sum += (((*(it + 1)) << 8) & 0xFF00) | *(it);

        if ((it + 1) == this->rest_of_message.end())
        {
            break;
        }
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    this->checksum = result;
}