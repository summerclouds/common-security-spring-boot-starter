package org.summerclouds.common.security.permissions;

import org.springframework.security.core.GrantedAuthority;

public interface Permissions extends GrantedAuthority {

	boolean hasPermission(String perm);
	
}
