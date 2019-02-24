package com.example.JWTAuthentication.security;

import com.example.JWTAuthentication.service.CustomUserDetailsService;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.example.JWTAuthentication.security.SecurityConstants.*;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private CustomUserDetailsService customUserDetailsService;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager,
                                  CustomUserDetailsService customUserDetailsService) {
        super(authenticationManager);
        this.customUserDetailsService = customUserDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //Extraemos el value del header con key Authorize
        String header = request.getHeader(HEADER_KEY);

        // Chequemos si el header con key 'Authorize' su valor empieza con 'Bearer'
        if ( header == null || !header.startsWith(PREFIX_TOKEN) ) {
            chain.doFilter(request, response);
            return;
        }
        // Si el if anterior no se cumple quire decir que el usuario tiene un token jwt,
        // lo que resta es chequear si el token es valido (legal) para futuras request y de esto se encarga getAuthenticationToken
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = getAuthenticationToken(request);
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthenticationToken (HttpServletRequest request){
        //Extraemos el value del header con key Authorize
        String token = request.getHeader(HEADER_KEY);

        if (token == null) return null;

        String username = Jwts.parser()
                            .setSigningKey(SECRET)
                            .parseClaimsJws(token.replace(PREFIX_TOKEN,  ""))
                            .getBody()
                            .getSubject(); //getSubject nos retorna el username, ya que ahi le seteamos el username usando setSubject al token

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

        return ( username != null )?
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities())
                :
                null;
    }
}
