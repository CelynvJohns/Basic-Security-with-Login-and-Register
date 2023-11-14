package travel.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import travel.model.Role;
import travel.repository.RoleRepository;
import travel.repository.UserRepository;

@Service
public class UserService implements UserDetailsService {

	// Repositorys and encoders
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final PasswordEncoder passwordEncoder;

	// calling repositories and encoders
	public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, RoleRepository roleRepository) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.roleRepository = roleRepository;
	}

	// gets User by Username, to make sure that the User exists
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<travel.model.User> userOptional = Optional.of(userRepository.findByUsername(username));

		if (userOptional.isPresent()) {
			travel.model.User user = userOptional.get();
			return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
					Collections.singletonList(new SimpleGrantedAuthority("USER")));
		} else {
			throw new UsernameNotFoundException("User not found with username: " + username);
		}
	}

	// registers the user
	public travel.model.User registerUser(String username, String password) {
		travel.model.User existingUser = userRepository.findByUsername(username);

		if (username == null || password == null || username.isEmpty() || password.isEmpty()
				|| !isValidPassword(password) || existingUser != null) {
			return null;
		} else {
			travel.model.User user = new travel.model.User();
			user.setUsername(username);
			user.setPassword(passwordEncoder.encode(password));

			// Assign the user to the USER role by default
			Role userRole = roleRepository.findByName("USER");
			Set<Role> roles = new HashSet<>();
			roles.add(userRole);
			user.setRoles(roles);

			return userRepository.save(user);
		}
	}

	// authenticates the login
	public UserDetails authenticate(String username, String password) {
		UserDetails userDetails = loadUserByUsername(username);

		if (userDetails != null && passwordEncoder.matches(password, userDetails.getPassword())) {
			return userDetails;
		} else {
			return null;
		}
	}

	// checks if password is valid
	private boolean isValidPassword(String password) {
		String passwordRegex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$";
		return password.matches(passwordRegex);
	}
}
