package travel.wrappers;

import lombok.AllArgsConstructor;
import travel.model.User;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

@AllArgsConstructor
public class UserWrapper implements UserDetails {

	// serial UID
	private static final long serialVersionUID = 1L;

	// Variable
	private User user;

	// gets the user's role
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return user.getRoles().stream().map(role -> new RoleWrapper(role.getName())).collect(Collectors.toList());
	}

	// gets user password
	@Override
	public String getPassword() {
		return user.getPassword();
	}

	// get user username
	@Override
	public String getUsername() {
		return user.getUsername();
	}

	// makes sure account is not expired
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	// makes sure account isn't locked
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	// makes sure the credentials are not expired
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	// makes sure account is enabled
	@Override
	public boolean isEnabled() {
		return true;
	}

	// all args constructor
	public UserWrapper(User user) {
		super();
		this.user = user;

	}

	// no args constructor
	public UserWrapper() {
		super();
	}

}