package fr.mahugnon.jwtlearning.services;

import fr.mahugnon.jwtlearning.domain.AppUser;
import fr.mahugnon.jwtlearning.domain.Role;
import fr.mahugnon.jwtlearning.repositories.AppUserRepository;
import fr.mahugnon.jwtlearning.repositories.RoleRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service @AllArgsConstructor
@Transactional @Slf4j
public class AppUserServiceImpl implements AppUserService, UserDetailsService {

    AppUserRepository appUserRepository;
    RoleRepository roleRepository;
    BCryptPasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = appUserRepository.findByUsername(username);
        if(appUser == null){
            log.error("User {} not found in the database", username);
            throw new UsernameNotFoundException("User not found in the database");
        }else{
            log.info("User {} found in the database", username);
        }
     Collection<GrantedAuthority> authorities = appUser.roles().stream().map(r->new SimpleGrantedAuthority(r.getName())).collect(Collectors.toList());
        return new User(appUser.getUsername(),appUser.getPassword(),authorities);
    }
    @Override
    public AppUser saveAppUser(AppUser appUser) {
        log.info("Saving new user {} to the database",appUser.getName());
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        return appUserRepository.save(appUser);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role {} to the database",role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role {} to user {}", roleName,username);
        var user = appUserRepository.findByUsername(username);
        var role = roleRepository.findByName(roleName);
        user.addRole(role);
    }

    @Override
    public AppUser getAppUser(String username) {
        log.info("Fetching  user {} from the database",username);
        return appUserRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> getAppUsers() {
        log.info("Fetching all users from the database");
        return appUserRepository.findAll();
    }


}
