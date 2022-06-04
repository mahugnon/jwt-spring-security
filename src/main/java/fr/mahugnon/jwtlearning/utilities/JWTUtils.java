package fr.mahugnon.jwtlearning.utilities;

import java.util.Date;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class JWTUtils{

    public  String generateToken(User user, Date expDate, String issuer){
  
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(expDate)
                .withIssuer(issuer)
                .withClaim("roles",user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);
        

    }
}