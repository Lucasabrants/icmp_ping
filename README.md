# icmp_ping
Implementação do envio de mensagens icmp, com exemplo de uso para a mensagem de ping

Para gerar o binário execute o comando:
```
make
```

Com o binário gerado, para executar o exemplo precisa de privilégios root já que a aplicação utiliza socket, então utilize:
```
sudo ./build/ping <hostname/ip address>
```

Exemplo:
```
sudo ./build/ping google.com
```
