package org.summerclouds.common.security.realm;

import java.util.HashSet;
import java.util.Set;

public class MemoryRoleRealm implements RoleRealm {

	private Set<String> roles = new HashSet<>();
	
	
	@Override
	public Role getRole(final String rolename) {
		if (roles.contains(rolename))
			return new Role() {

				@Override
				public String getRolename() {
					return rolename;
				}

				@Override
				public boolean isEnabled() {
					return true;
				}

				@Override
				public boolean isAccountNonLocked() {
					return true;
				}
			
		};

		return null;
	}

	public MemoryRoleRealm add(String name) {
		roles.add(name);
		return this;
	}

	@Override
	public boolean isEnabled() {
		return !roles.isEmpty();
	}
}
