package com.example.JWTAuthentication.service;

import com.example.JWTAuthentication.model.Usuario;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Component
public class CustomUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String s) {
        Usuario usuario = loadUsuarioFromBD(s);

        UserDetails user = User.withDefaultPasswordEncoder()
                .username(usuario.getUsername())
                .password(usuario.getPassword())
                .roles("USER")
                .build();
        return user;
    }

    private Usuario loadUsuarioFromBD(String username) {
        // DB call aqui
        return new Usuario("batman", "123");
    }

}
