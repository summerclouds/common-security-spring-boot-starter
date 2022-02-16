package org.summerclouds.common.security.realm;

public interface Role {

	/**
	 * Returns the rolename used to assign the role to the user. Cannot return
	 * <code>null</code>.
	 * @return the rolename (never <code>null</code>)
	 */
	String getRolename();

	/**
	 * Indicates whether the role is enabled or disabled. A disabled role will be ignored.
	 * 
	 * @return <code>true</code> if the user is enabled, <code>false</code> otherwise
	 */
	boolean isEnabled();

	/**
	 * Indicates whether the role is locked or unlocked. A user in a locked role cannot be
	 * authenticated.
	 * @return <code>true</code> if the user is not locked, <code>false</code> otherwise
	 */
	boolean isAccountNonLocked();

	
}
