package fr.mahugnon.jwtlearning.repositories;

import fr.mahugnon.jwtlearning.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role,Long> {
Role findByName(String name);
}
