package travel.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import travel.model.Role;
import travel.repository.RoleRepository;

@Service
public class RoleService {

    @Autowired
    private RoleRepository roleRepository;

    public void createDefaultRoles() {
        Role adminRole = new Role();
        adminRole.setName(Role.RoleName.ADMIN);

        Role bloggerRole = new Role();
        bloggerRole.setName(Role.RoleName.BLOGGER);

        Role userRole = new Role();
        userRole.setName(Role.RoleName.USER);

        roleRepository.save(adminRole);
        roleRepository.save(bloggerRole);
        roleRepository.save(userRole);
    }
}
