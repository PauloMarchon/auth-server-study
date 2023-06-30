package com.paulomarchon.authserver.client;

import com.paulomarchon.authserver.client.payload.ClientDto;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.function.Function;

@Service
public class ClientDtoMapper implements Function<Client, ClientDto> {
    @Override
    public ClientDto apply(Client client) {
        return null;
    }
}
