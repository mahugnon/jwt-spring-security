package fr.mahugnon.jwtlearning.utilities;

import java.util.Date;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import fr.mahugnon.jwtlearning.domain.Role;
import lombok.Getter;

public class JWTUtils{

    public  String generateToken(User user, Date expDate, String issuer, Boolean isRefresh){
  
 var builder = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(expDate)
                .withIssuer(issuer);
 if(!isRefresh){
     builder .withClaim("roles",user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));

 }
     return builder.sign(this.getAlgorithm());
        

    }


    public Algorithm getAlgorithm() {
        return   Algorithm.HMAC256("secret".getBytes());
        
    }
   


}