package com.example.JWTAuthentication.security;

import com.example.JWTAuthentication.model.Usuario;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static com.example.JWTAuthentication.security.SecurityConstants.*;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    // {"username" : "batman", "password" : "123"}
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response){
        // request.getInputStream() : eso nos retorna el json {"username" : "batman", "password" : "123"} del body
        try{
            // 1 - Inicializamos un usuario con el json que viene en el body del request
            Usuario usuario = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);
            // 2 - Usamos el AuthenticationManager para que autentique a dicho usuario.
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(usuario.getUsername(), usuario.getPassword())
            );
        }catch(IOException e){
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        // 1 - expirationTimeUTC va a ser la fecha de expiracion del token
        ZonedDateTime expirationTimeUTC = ZonedDateTime.now(ZoneOffset.UTC).plus(EXPIRATION_TIME, ChronoUnit.MILLIS);

        // 2 - Armamos el token (authResult es el usuario que fue autenticado recien es decir que recien pasó por el metodo anterior)
        String token = Jwts.builder()
                             .setSubject(((User)authResult.getPrincipal()).getUsername())
                             .setExpiration(Date.from(expirationTimeUTC.toInstant()))
                             .signWith(SignatureAlgorithm.HS256, SECRET)
                             .compact();

        // 3 - Agregamos el token al response
        response.addHeader(HEADER_KEY, PREFIX_TOKEN + token); //Lo agrega al header del response al token

        response.getWriter().write(token); // Lo agreda dentro del body del response al token
    }
}
