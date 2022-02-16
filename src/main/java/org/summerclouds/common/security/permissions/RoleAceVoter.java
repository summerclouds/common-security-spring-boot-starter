package org.summerclouds.common.security.permissions;

import java.util.Collection;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class RoleAceVoter implements AccessDecisionVoter<Object> {

	private String rolePrefixUpper = "ROLE_";
	private String rolePrefixLower = "role_";
	public static final String ROLE_PERMISSION = "role"+WildcardAce.PART_DIVIDER_TOKEN+"access" + WildcardAce.PART_DIVIDER_TOKEN;
	private boolean legacy = true;

	public String getRolePrefix() {
		return this.rolePrefixUpper;
	}

	/**
	 * Allows the default role prefix of <code>ROLE_</code> to be overridden. May be set
	 * to an empty value, although this is usually not desirable.
	 * @param rolePrefix the new prefix
	 */
	public void setRolePrefix(String rolePrefix) {
		this.rolePrefixUpper = rolePrefix.toUpperCase();
		this.rolePrefixLower = rolePrefix.toLowerCase();
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		String value = toString(attribute);
		return value != null && (value.startsWith(rolePrefixUpper) || value.startsWith(rolePrefixLower));
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

	/**
	 * This implementation supports any type of class, because it does not query the
	 * presented secure object.
	 * @param clazz the secure object
	 * @return always <code>true</code>
	 */
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
				String roleAsPermission = ROLE_PERMISSION + toString(attribute);
				result = ACCESS_DENIED;
				// Attempt to find a matching granted authority
				for (GrantedAuthority authority : authorities) {
					if (	authority instanceof PermissionSet &&
							((PermissionSet)authority).hasPermission(roleAsPermission) )
							return ACCESS_GRANTED;
					else
					if (legacy && attribute.getAttribute().equals(authority.getAuthority())) {
						return ACCESS_GRANTED;
					}
				}
			}
		}
		return result;
	}

	Collection<? extends GrantedAuthority> extractAuthorities(Authentication authentication) {
		return authentication.getAuthorities();
	}

}
