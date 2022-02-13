package org.sommerclouds.common.security;

import java.util.Collection;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

// https://github.com/spring-projects/spring-security/blob/006b9b960797d279b31cf8c8d16f1549c5632b2c/core/src/main/java/org/springframework/security/access/vote/RoleVoter.java
// https://www.baeldung.com/spring-security-custom-voter
// https://octoperf.com/blog/2018/03/08/securing-rest-api-spring-security/#user-crud-api
// https://www.marcobehler.com/guides/spring-security
public class PermissionVoter implements AccessDecisionVoter<Object> {

	private String permissionPrefix = "RULE_asjgh:*:*";
	
	@Override
	public boolean supports(ConfigAttribute attribute) {
		return (attribute.getAttribute() != null) && attribute.getAttribute().startsWith(getPermissionPrefix());
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}

	@Override
	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
		
		return 0;
	}

	public String getPermissionPrefix() {
		return permissionPrefix;
	}

	public void setPermissionPrefix(String permissionPrefix) {
		this.permissionPrefix = permissionPrefix;
	}

}
