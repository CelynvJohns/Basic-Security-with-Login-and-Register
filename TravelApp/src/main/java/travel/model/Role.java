package travel.model;


import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Entity
@Getter
@Setter
@Table(name = "roles")
public class Role {

	// variables, RoleName is enum so that only 3 are accepted
    public enum RoleName {
        ADMIN, BLOGGER, USER
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private RoleName name;

    @ManyToMany(mappedBy = "roles")
    private Set<User> users;

    // Empty Constructors
    public Role() {
    	super();
    }

    // Basic Role Constructor
    public Role(RoleName name, Set<User> users) {
        this.name = name;
        this.users = users;
    }

    // implementing getters and setters, because Lombok doens't work on my laptop
    /**
	 * @return the id
	 */
	public int getId() {
		return id;
	}

	/**
	 * @param id the id to set
	 */
	public void setId(int id) {
		this.id = id;
	}

	/**
	 * @return the name
	 */
	public RoleName getName() {
		return name;
	}

	/**
	 * @param name the name to set
	 */
	public void setName(RoleName name) {
		this.name = name;
	}

	/**
	 * @return the users
	 */
	public Set<User> getUsers() {
		return users;
	}

	/**
	 * @param users the users to set
	 */
	public void setUsers(Set<User> users) {
		this.users = users;
	}

    // implemented toString
    @Override
    public String toString() {
        return "Role [id=" + id + ", name=" + name + ", users=" + users + "]";
    }

	
}
