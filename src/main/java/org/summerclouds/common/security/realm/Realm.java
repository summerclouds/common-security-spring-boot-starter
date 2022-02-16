package org.summerclouds.common.security.realm;

public interface Realm {
	
	/**
	 * Return true if the realm is active.
	 * 
	 * @return
	 */
	boolean isEnabled();
	
}
