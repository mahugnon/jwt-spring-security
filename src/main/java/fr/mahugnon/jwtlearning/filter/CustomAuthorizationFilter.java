package fr.mahugnon.jwtlearning.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import fr.mahugnon.jwtlearning.utilities.JWTUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
                JWTUtils jwtUtils = new JWTUtils();
                if(request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")){
                    filterChain.doFilter(request, response);
                } else{
                    try {
                        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
                        if(!authorizationHeader.isBlank() && authorizationHeader.startsWith("Bearer ")){
                            String token = authorizationHeader.substring("Bearer ".length());
                            JWTVerifier verifier = JWT.require(jwtUtils.getAlgorithm()).build();
                            DecodedJWT decodedJWT = verifier.verify(token);
                            String username = decodedJWT.getSubject();
                            String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                            var authorities = Stream.of(roles).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
                            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                            
                        }
                        filterChain.doFilter(request, response);
                    } catch (Exception e) {
                        log.error("Error in loggin : {}", e.getMessage());
                        response.setHeader("Error", e.getMessage());
                        //response.sendError();
                        response.setStatus(HttpStatus.FORBIDDEN.value());
                        Map<String,String> error = new HashMap<>();
                        error.put("error_message", e.getMessage());
                        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                        new ObjectMapper().writeValue(response.getOutputStream(),error);
                    }
                  
                }

        
    }
    
}
