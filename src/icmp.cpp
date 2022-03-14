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
#define MAX_TTL_VALUE 255
#define ICMP_TTL_INDEX 8
#define ICMP_SOURCE_ADDRESS_INDEX 12
#define ICMP_DESTINATION_ADDRESS_INDEX 16
#define ICMP_REST_OF_MESSAGE_INDEX 24

/* IP Protocol + Internet Control Message Protocol(ECHO Request/Reply)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Version | IHL | TOS/DSCP/ECN  |        Total Length           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Identification         |Flags |   Fragment Offset      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     TTL      |   Protocol     |      Header Checksum          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Source Address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Destination Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-
*/

/**
 * @brief Construtor padrão
 * 
 */
Icmp::Icmp()
{
    this->checksum = 0;
}

/**
 * @brief Construtor personalizado inicializa alguns parametros da mensagem de acordo com o tipo
 * 
 * @param type Tipo da mensgem
 * @param code 
 */
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

/**
 * @brief Insere na mensagem o restante dos bytes
 * 
 * @param message Dependendo do tipo da mensagem ICMP esse parametro tem um tamanho máximo diferente,
 *        caso esse limite seja excedido é gerada uma exceção
 */
void Icmp::set_last_parameters(std::vector<unsigned char> &message)
{
    if (message.size() > this->rest_of_message.size())
    {
        std::cout << "Tamanho da mensagem maior que o tamanho máximo do tipo definido, MAX_SIZE("
        << ICMP_PING_SIZE << ")\n";
        throw;
    }

    for (int i = 0; i < message.size(); i++)
    {
        this->rest_of_message.at(i) = message.at(i);
    }
}

/**
 * @brief Serializa os parâmetros da mensagem ICMP
 * 
 * @return std::vector<unsigned char> 
 */
std::vector<unsigned char> Icmp::encode()
{
    std::vector<unsigned char> message;
    this->checksum_calc();

    message.push_back(static_cast<unsigned char>(this->type));
    message.push_back(this->code);
    message.push_back(static_cast<unsigned char>(this->checksum & 0xFF));
    message.push_back(static_cast<unsigned char>((this->checksum >> 8) & 0xFF));
    message.insert(message.end(), this->rest_of_message.begin(), this->rest_of_message.end());

    return message;
}

/**
 * @brief Decodifica uma mensagem do procolo Ip + ECHO Reply 
 * 
 * @param message 
 * @param ttl 
 * @param source_address 
 * @param destination_address 
 * @param rest_of_message 
 */
void Icmp::decode(std::vector<unsigned char> &message, unsigned char * ttl, 
               unsigned int *source_address, unsigned int *destination_address,
               std::shared_ptr<std::vector<unsigned char>> rest_of_message)
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

    if (rest_of_message)
    {
        rest_of_message->clear();
        rest_of_message->insert(rest_of_message->begin(), message.begin() + ICMP_REST_OF_MESSAGE_INDEX, message.end());
    }
}

/**
 * @brief Calcula preenche o campo checksum com a soma de verificação dos bytes da mensagem ICMP
 * 
 * @param message 
 */
void Icmp::checksum_calc()
{
    unsigned int sum = 0;
    unsigned short result;

    sum += ((this->code << 8) & 0xFF00) | static_cast<unsigned char>(this->type);
    
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
