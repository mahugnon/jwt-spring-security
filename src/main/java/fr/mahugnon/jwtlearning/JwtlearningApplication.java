package fr.mahugnon.jwtlearning;

import fr.mahugnon.jwtlearning.domain.AppUser;
import fr.mahugnon.jwtlearning.domain.Role;
import fr.mahugnon.jwtlearning.services.AppUserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.HashSet;

@SpringBootApplication
public class JwtlearningApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtlearningApplication.class, args);
    }
@Bean
    BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
}
    @Bean
    CommandLineRunner run(AppUserService service){
        return args ->{
    service.saveRole(new Role(null,"ROLE_USER"));
    service.saveRole(new Role(null,"ROLE_MANAGER"));
    service.saveRole(new Role(null,"ROLE_ADMIN"));
    service.saveRole(new Role(null,"ROLE_SUPER_ADMIN"));

    service.saveAppUser(new AppUser(null,"HOUEKPETODJI Denis","depnik","1234",new HashSet<>()));
    service.saveAppUser(new AppUser(null,"KOUTON ETIENNE DOSSA","etienne","1234",new HashSet<>()));
    service.saveAppUser(new AppUser(null,"TEVOEDJRE ANGELO","angelo","1234",new HashSet<>()));
    service.saveAppUser(new AppUser(null,"MITCHODJEHOUN HUBERT","hubert","1234",new HashSet<>()));
    service.saveAppUser(new AppUser(null,"HOUEKPETODJI HONORE","honore","1234",new HashSet<>()));

    service.addRoleToUser("depnik","ROLE_ADMIN");
    service.addRoleToUser("hubert","ROLE_MANAGER");
    service.addRoleToUser("etienne","ROLE_USER");
    service.addRoleToUser("angelo","ROLE_USER");
    service.addRoleToUser("honore","ROLE_SUPER_ADMIN");
    service.addRoleToUser("honore","ROLE_ADMIN");
    service.addRoleToUser("honore","ROLE_MANAGER");

        };
    }
}
