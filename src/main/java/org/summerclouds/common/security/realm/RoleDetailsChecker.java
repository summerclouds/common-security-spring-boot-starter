package org.summerclouds.common.security.realm;

public interface RoleDetailsChecker {

	/**
	 * check the role status and return true if the role is ok or false
	 * if the role should be ignored.
	 * 
	 * @param role
	 * @return
	 */
	boolean check(Role role);

}
