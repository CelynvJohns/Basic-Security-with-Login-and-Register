package travel.wrappers;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import travel.model.Role;

@Getter
@AllArgsConstructor
public class RoleWrapper implements GrantedAuthority {
	// SerialUID
	private static final long serialVersionUID = 1L;

	// getting name from Role.RoleName
	private Role.RoleName roleName;

	// gets authority
	@Override
	public String getAuthority() {
		return roleName.name();
	}

	// no args constructor
	public RoleWrapper() {
		super();
	}

	// all args constructor
	public RoleWrapper(Role.RoleName roleName) {
		super();
		this.roleName = roleName;
	}
}
