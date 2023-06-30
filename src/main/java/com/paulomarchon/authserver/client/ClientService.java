package com.paulomarchon.authserver.client;

import com.paulomarchon.authserver.client.payload.RegisterClientDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClientService implements RegisteredClientRepository {

    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = clientRepository.findByClientId(id)
                .orElseThrow(()-> new RuntimeException("client not found"));
        return Client.toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(()-> new RuntimeException("client not found"));
        return Client.toRegisteredClient(client);
    }

    public void create(RegisterClientDto dto){
        Client client = clientFromDto(dto);
        clientRepository.save(client);
    }

    // private methods
    private Client clientFromDto(RegisterClientDto dto){
        return Client.builder()
                .clientId(dto.clientId())
                .clientSecret(passwordEncoder.encode(dto.clientSecret()))
                .authenticationMethods(dto.authenticationMethods())
                .authorizationGrantTypes(dto.authorizationGrantTypes())
                .redirectUris(dto.redirectUris())
                .scopes(dto.scopes())
                .requireProofKey(dto.requireProofKey())
                .build();
    }

}
