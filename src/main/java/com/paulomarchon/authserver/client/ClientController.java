package com.paulomarchon.authserver.client;

import com.paulomarchon.authserver.client.payload.RegisterClientDto;
import com.paulomarchon.authserver.common.MessageDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/client")
@RequiredArgsConstructor
@Slf4j
public class ClientController {

    private final ClientService clientService;

    @PostMapping("/register")
    public ResponseEntity<?> create(@RequestBody RegisterClientDto dto){
        clientService.create(dto);

        MessageDto messageDto = new MessageDto("client registered successfully");

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(messageDto);    }
}
