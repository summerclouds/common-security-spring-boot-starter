package org.summerclouds.common.security.realm;

public class DefaultRoleDetailsChecker implements RoleDetailsChecker {

	@Override
	public boolean check(Role role) {
		
		if (!role.isEnabled()) return false;
		
		if (!role.isAccountNonLocked()) return false;
		
		return true;
	}

}
