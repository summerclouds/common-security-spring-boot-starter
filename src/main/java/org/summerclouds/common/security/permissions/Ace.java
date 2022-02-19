package org.summerclouds.common.security.permissions;
/**
 * Format: object:action:intance:description
 * @author mikehummel
 *
 */
public class Ace {

    // default rights
    public static final String READ = "read";
    public static final String CREATE = "create";
    public static final String UPDATE = "update";
    public static final String DELETE = "delete";
    public static final String VIEW = "view";
    public static final String ADMIN = "admin";
    public static final String EXECUTE = "execute";

    public static final String WILDCARD_TOKEN = "*";
    public static final String PART_DIVIDER_TOKEN = ":";
    public static final String SUBPART_DIVIDER_TOKEN = ",";
	public static final String ACE_DIVIDER = ";";

	private String object;
	
	private String action;
	
	private String instance;
	
	private String description = "";

	public Ace(String object, String action, String instance) {
		this.object = object == null ? WILDCARD_TOKEN : normalize(object);
		this.action = action == null ? WILDCARD_TOKEN : normalize(action);
		this.instance = instance == null ? WILDCARD_TOKEN : normalize(instance);
	}

	public Ace(String perm) {
		
		String[] parts = perm.split(PART_DIVIDER_TOKEN, 4);
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
			
		this.object = object == null ? WILDCARD_TOKEN : normalize(object);
		this.action = action == null ? WILDCARD_TOKEN : normalize(action);
		this.instance = instance == null ? WILDCARD_TOKEN : normalize(instance);
		
	}
	
	public static String normalize(String str) {
		if (str.indexOf(PART_DIVIDER_TOKEN) > -1)
			str = str.replace(PART_DIVIDER_TOKEN, "_");
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
		return object + PART_DIVIDER_TOKEN + action + PART_DIVIDER_TOKEN + instance + PART_DIVIDER_TOKEN + description;
	}

	public static String normalize(String object, String action, String instance) {
		return normalize(object) + PART_DIVIDER_TOKEN + normalize(action) + PART_DIVIDER_TOKEN + normalize(instance);
	}
	
}
