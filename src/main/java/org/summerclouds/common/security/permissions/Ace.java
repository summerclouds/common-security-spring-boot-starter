package org.summerclouds.common.security.permissions;

import org.summerclouds.common.core.tool.MSecurity;

/**
 * Format: object:action:intance:description
 * @author mikehummel
 *
 */
public class Ace {

	private String object;
	
	private String action;
	
	private String instance;
	
	private String description = "";

	public Ace(String object, String action, String instance) {
		this.object = object == null ? MSecurity.WILDCARD_TOKEN : normalize(object);
		this.action = action == null ? MSecurity.WILDCARD_TOKEN : normalize(action);
		this.instance = instance == null ? MSecurity.WILDCARD_TOKEN : normalize(instance);
	}

	public Ace(String perm) {
		
		String[] parts = perm.split(MSecurity.PART_DIVIDER_TOKEN, 4);
		String object = null;
		String action = null;
		String instance = null;
		if (parts.length > 0) {
			object = parts[0];
			if (parts.length > 1) {
				action = parts[1];
				if (parts.length > 2) {
					instance = parts[2];
					if (parts.length > 3)
						description = parts[3];
				}
			}
		}
			
		this.object = object == null ? MSecurity.WILDCARD_TOKEN : normalize(object);
		this.action = action == null ? MSecurity.WILDCARD_TOKEN : normalize(action);
		this.instance = instance == null ? MSecurity.WILDCARD_TOKEN : normalize(instance);
		
	}
	
	public static String normalize(String str) {
		if (str.indexOf(MSecurity.PART_DIVIDER_TOKEN) > -1)
			str = str.replace(MSecurity.PART_DIVIDER_TOKEN, "_");
		str = str.trim().toLowerCase();
		return str;
	}

	public String getObject() {
		return object;
	}

	public String getAction() {
		return action;
	}

	public String getInstance() {
		return instance;
	}	
	
	public String toString() {
		return object + MSecurity.PART_DIVIDER_TOKEN + action + MSecurity.PART_DIVIDER_TOKEN + instance + MSecurity.PART_DIVIDER_TOKEN + description;
	}

	public static String normalize(String object, String action, String instance) {
		return normalize(object) + MSecurity.PART_DIVIDER_TOKEN + normalize(action) + MSecurity.PART_DIVIDER_TOKEN + normalize(instance);
	}
	
}
