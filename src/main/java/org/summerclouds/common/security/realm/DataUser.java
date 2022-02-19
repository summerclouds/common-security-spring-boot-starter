package org.summerclouds.common.security.realm;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class DataUser extends User implements UserData {

	private static final long serialVersionUID = 1L;
	private Map<String, String> data;

	public DataUser(String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities, Map<String, String> data) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
		this.data = data;
	}

	public DataUser(String username, String password, Collection<? extends GrantedAuthority> authorities, Map<String, String> data) {
		super(username, password, authorities);
		this.data = data;
	}

	@Override
	public Map<String, String> getUserData() {
		return data;
	}

}
