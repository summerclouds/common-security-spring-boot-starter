package org.summerclouds.common.security;

import org.springframework.security.access.ConfigAttribute;

public class ConfigAttributeImpl implements ConfigAttribute {

	private static final long serialVersionUID = 1L;
	private String attribute;

	public ConfigAttributeImpl(String attribute) {
		this.attribute = attribute;
	}
	
	@Override
	public String getAttribute() {
		return null;
	}

	public String toString() {
		return "hasAuthority('" + attribute + "')";
	}
}
