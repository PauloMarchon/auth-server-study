package com.paulomarchon.authserver.client;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;


public interface ClientRepository extends JpaRepository<Client, UUID> {
    Optional<Client> findByClientId(String cliendId);
}
