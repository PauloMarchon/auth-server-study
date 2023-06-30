package com.paulomarchon.authserver.client.payload;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.Set;

public record RegisterClientDto(
        String clientId,
        String clientSecret,
        Set<ClientAuthenticationMethod> authenticationMethods,
        Set<AuthorizationGrantType> authorizationGrantTypes,
        Set<String> redirectUris,
        Set<String> scopes,
        boolean requireProofKey
) {
}
