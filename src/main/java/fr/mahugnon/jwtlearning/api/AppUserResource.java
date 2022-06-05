package fr.mahugnon.jwtlearning.api;

import fr.mahugnon.jwtlearning.domain.AppUser;
import fr.mahugnon.jwtlearning.domain.Role;
import fr.mahugnon.jwtlearning.services.AppUserService;
import fr.mahugnon.jwtlearning.utilities.JWTUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController @RequiredArgsConstructor
@Slf4j
@RequestMapping("/api")
public class AppUserResource {
    private final AppUserService appUserService;

    @GetMapping("/users")
    public ResponseEntity<List<AppUser>> getAppUsers(){
        return ResponseEntity.ok().body(appUserService.getAppUsers());
    }
    @PostMapping("/user/save")
    public ResponseEntity<AppUser> saveAppUser(@RequestBody AppUser user){
        return ResponseEntity.created(getURI("/user/save")).body(appUserService.saveAppUser(user));
    }
    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role){
        return ResponseEntity.created(getURI("/role/save")).body(appUserService.saveRole(role));
    }
    @PostMapping("/role/addtouser")
    public ResponseEntity<?> saveRole(@RequestBody RoleToUserForm form){
        appUserService.addRoleToUser(form.username, form.roleName);
        return ResponseEntity.ok().build();
    }
    @GetMapping("/token/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response){
        JWTUtils jwtUtils = new JWTUtils();
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        try{
        if(authorizationHeader.isBlank() && authorizationHeader.startsWith("Bearer "))throw new RuntimeException("Refresh token is missing");
          
            String refreshToken = authorizationHeader.substring("Bearer ".length());
            JWTVerifier verifier = JWT.require(jwtUtils.getAlgorithm()).build();
            DecodedJWT decodedJWT = verifier.verify(refreshToken);
            String username = decodedJWT.getSubject();
           AppUser appUser = appUserService.getAppUser(username);
           var authorities = appUser.roles().stream().map(r->new SimpleGrantedAuthority(r.getName())).collect(Collectors.toList());
          User user =  new User(username, appUser.getPassword(), authorities);
          String issuer =  request.getRequestURL().toString();
          String accessToken  = jwtUtils.generateToken(user, new Date(System.currentTimeMillis()+(10*60*1000)), issuer, false);
        fr.mahugnon.jwtlearning.utilities.Token token = new fr.mahugnon.jwtlearning.utilities.Token(accessToken, refreshToken);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(),token);
    } catch (Exception e) {
        log.error("Error in loggin : {}", e.getMessage());
        response.setHeader("Error", e.getMessage());
        //response.sendError();
        response.setStatus(HttpStatus.FORBIDDEN.value());
        Map<String,String> error = new HashMap<>();
        error.put("error_message", e.getMessage());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            try {
                new ObjectMapper().writeValue(response.getOutputStream(),error);
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }
        return ResponseEntity.ok().build();
    }
    private URI getURI(String path) {
    return URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api"+path).toUriString());
    }

}
@Data
 class RoleToUserForm {
     String username;
     String roleName;
 }
