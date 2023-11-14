package travel.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import travel.model.User;

public interface UserRepository extends JpaRepository<User, Integer> {

	// finds if the user is in the database
    Optional<User> findByUsernameAndPassword(String username, String password);
    
    // find the username
    User findByUsername(String username);
}