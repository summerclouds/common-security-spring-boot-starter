package org.summerclouds.common.security.realm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.Assert;
import org.summerclouds.common.security.permissions.PermSet;
import org.summerclouds.common.security.permissions.RoleAceVoter;
import org.summerclouds.common.security.permissions.Perm;

public abstract class AbstractUserRealm implements UserRealm {
	
	@Autowired
	private RealmManager manager;
	
	
	@Autowired(required = false)
	RoleDetailsChecker roleDetailsChecker = new DefaultRoleDetailsChecker();


	private boolean createRoleAce = true;


	private boolean createRoleAccess = true;
	
	@Override
	public User getUser(String username) {
		Assert.notNull(manager, "User manager not found");
		
		List<PermSet> acls = new ArrayList<>();
		Set<String> additionalAccess = new HashSet<>();
		
		// load user acls
		PermSet userAcl = manager.loadAclForUsername(username);
		if (userAcl != null)
			acls.add(userAcl);
		// load role acls
		Set<String> roles = manager.loadRolesByUsername(username);
		if (roles != null) {
			Set<String> roleAccess = new HashSet<>();
			for (String rolename : roles) {
				// get role
				Role role = manager.loadRoleByRolename(rolename);
				if (role != null) {
					if (roleDetailsChecker.check(role)) {
						PermSet roleAcl = manager.loadAclForRole(rolename);
						if (roleAcl != null)
							acls.add(roleAcl);
						
						if (createRoleAce) {
							String roleAce = createRoleAccessEntry(rolename);
							if (roleAce != null)
								roleAccess.add(roleAce);
						}
						if (createRoleAccess)
							additionalAccess.add(rolename.toUpperCase());
					}
						
				}
			}
			if (!roleAccess.isEmpty())
				acls.add(new PermSet(roleAccess));
		}
		
		// join acls
		PermSet newAcl = null;
		Set<String> newAces = new HashSet<>();
		for (PermSet acl : acls) {
			for (Perm ace : acl) {
				newAces.add( ace.toString() );
			}
		}
		newAcl = new PermSet(newAces);
		
		Map<String, String> data = new HashMap<>();
		manager.loadUserData(username, data);
		
		return createUser(username, newAcl, data);
	}

	protected String createRoleAccessEntry(String rolename) {
		return RoleAceVoter.ROLE_ACE + rolename;
	}

	protected abstract User createUser(String username, PermSet acl, Map<String, String> data);

}
