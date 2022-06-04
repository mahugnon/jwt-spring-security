package fr.mahugnon.jwtlearning.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


import java.util.*;

import static jakarta.persistence.FetchType.EAGER;
import static jakarta.persistence.GenerationType.AUTO;

@Entity @Data @NoArgsConstructor
@AllArgsConstructor
public class AppUser {
    @Id @GeneratedValue(strategy = AUTO)
    private Long id;
    private String name;
    private String username;
    private String password;
    @ManyToMany(fetch = EAGER)
    private Set<Role> roles = new HashSet<>();

    public void addRole(Role role) {
      roles.add(role);
    }
    public Set<Role> roles() {
     return Collections.unmodifiableSet(roles);
    }
    public void removeRole(Role role) {
        roles.remove(role);
    }
}
