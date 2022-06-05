package fr.mahugnon.jwtlearning.filter;

import com.fasterxml.jackson.databind.ObjectMapper;

import fr.mahugnon.jwtlearning.utilities.JWTUtils;
import fr.mahugnon.jwtlearning.utilities.Token;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
      String username = request.getParameter("username");
      String password = request.getParameter("password");
      log.info("User is {} and the password is {}",username, password);
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username,password);
       return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        User user = (User)authentication.getPrincipal();
        var jwtUtils = new JWTUtils();  
       String issuer =  request.getRequestURL().toString();
       String accessToken  = jwtUtils.generateToken(user, new Date(System.currentTimeMillis()+(10*60*1000)), issuer,false);
       String refreshToken = jwtUtils.generateToken(user, new Date(System.currentTimeMillis()+(30*60*1000)), issuer,true);
       Token token = new Token(accessToken, refreshToken);
       response.setContentType(MediaType.APPLICATION_JSON_VALUE);
       new ObjectMapper().writeValue(response.getOutputStream(),token);
     //   response.setHeader("access_token", accessToken);
    //  response.addHeader("refresh_token", refreshToken);
    }
}
