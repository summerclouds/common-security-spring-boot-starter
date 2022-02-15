package org.summerclouds.common.security.permissions;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.core.parser.StringCompiler;

public class ResourceAceVoter implements AccessDecisionVoter<Object> {

	public static final String PREFIX_UPPER = "ACE_";
	public static final String PREFIX_LOWER = "ace_";
	
	@Override
	public boolean supports(ConfigAttribute attribute) {
		String value = toString(attribute);
		return value != null && (value.startsWith(PREFIX_UPPER) || value.startsWith(PREFIX_LOWER));
	}
	
	public String toString(ConfigAttribute attribute) {
		String value = null;
		if (attribute.getAttribute() != null) {
			value = attribute.getAttribute();
		} else {
			String str = attribute.toString();
			if (str != null && str.startsWith("hasAuthority('")) {
				value = str.substring(14, str.length() - 2);
			}
		}
		return value;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}

	@Override
	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
		
		if (authentication == null) {
			return ACCESS_DENIED;
		}
		int result = ACCESS_ABSTAIN;
		Collection<? extends GrantedAuthority> authorities = extractAuthorities(authentication);
		for (ConfigAttribute attribute : attributes) {
			if (this.supports(attribute)) {
				String attributePermission = prepareAttribute(toString(attribute), object);
				result = ACCESS_DENIED;
				for (GrantedAuthority authority : authorities)
					if (	authority instanceof PermissionSet &&
							((PermissionSet)authority).hasPermission( attributePermission ) )
							return ACCESS_GRANTED;
			}
		}
		
		return result; // it will not deny access, it only grants access
	}

	private String prepareAttribute(String attribute, Object object) {
		attribute = attribute.substring(PREFIX_UPPER.length());
		Map<String,Object> map = null;
		// TODO configurable
		if (object instanceof FilterInvocation) {
			map = new HashMap<>();
			map.put("method", ((FilterInvocation)object).getRequest().getMethod());
			map.put("url", ((FilterInvocation)object).getRequestUrl());;
			
		}
		if (map != null)
			try {
				attribute = StringCompiler.compile(attribute).execute(map);
			} catch (MException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		return attribute;
	}

	Collection<? extends GrantedAuthority> extractAuthorities(Authentication authentication) {
		return authentication.getAuthorities();
	}

}
