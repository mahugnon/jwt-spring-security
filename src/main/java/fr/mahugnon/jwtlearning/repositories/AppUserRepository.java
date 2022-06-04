package fr.mahugnon.jwtlearning.repositories;

import fr.mahugnon.jwtlearning.domain.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
