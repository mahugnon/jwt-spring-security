package fr.mahugnon.jwtlearning.api;

import fr.mahugnon.jwtlearning.domain.AppUser;
import fr.mahugnon.jwtlearning.domain.Role;
import fr.mahugnon.jwtlearning.services.AppUserService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RestController @RequiredArgsConstructor
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

    private URI getURI(String path) {
    return URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api"+path).toUriString());
    }

}
@Data
 class RoleToUserForm {
     String username;
     String roleName;
 }
