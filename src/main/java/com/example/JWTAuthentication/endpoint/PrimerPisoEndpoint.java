package com.example.JWTAuthentication.endpoint;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/piso1")
public class PrimerPisoEndpoint {

    @GetMapping("/oficina1")
    public ResponseEntity<?> ingresarOficina1(){
        return new ResponseEntity("Ingresaste a la oficina 1! ...", HttpStatus.OK);
    }

    @GetMapping("/oficina2")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<?> ingresarOficina2(){
        return new ResponseEntity("Ingresaste a la oficina 2! ...", HttpStatus.OK);
    }

}
