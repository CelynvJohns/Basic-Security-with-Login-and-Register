package travel.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import travel.model.Role;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    // You can add custom query methods if needed
    // For example, finding a role by name
    Role findByName(String name);
}
