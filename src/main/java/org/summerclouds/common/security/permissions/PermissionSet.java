package org.summerclouds.common.security.permissions;

import org.springframework.security.core.GrantedAuthority;

public interface PermissionSet extends GrantedAuthority {

	public boolean hasPermission(String perm);
	
}
