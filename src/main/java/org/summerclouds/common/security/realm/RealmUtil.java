package org.summerclouds.common.security.realm;

public class RealmUtil {

	/**
	 * Trim and lower case the name. If the name is null an empty
	 * string will be returned.
	 * 
	 * TODO Throw runtime exception if forbidden letters are found
	 * 
	 * @param name
	 * @return
	 */
	public static String normalize(String name) {
		if (name == null) return "";
		return name.trim().toLowerCase();
	}


}
