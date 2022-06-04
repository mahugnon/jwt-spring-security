package fr.mahugnon.jwtlearning.services;

import fr.mahugnon.jwtlearning.domain.AppUser;
import fr.mahugnon.jwtlearning.domain.Role;

import java.util.List;

public interface AppUserService {
    AppUser saveAppUser(AppUser appUser);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    AppUser getAppUser(String usename);
    List<AppUser> getAppUsers();
}
