package org.summerclouds.common.security.realm;

import java.util.Map;
import java.util.Set;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.summerclouds.common.core.log.MLog;
import org.summerclouds.common.core.tool.MSpring;
import org.summerclouds.common.security.permissions.Acl;

public class RealmManager extends MLog implements UserDetailsService {

//	@Autowired
	private Map<String, Realm> realms;

	protected synchronized void loadRealms() {
		if (realms != null) return;
		realms = MSpring.getBeansOfType(Realm.class);
		log().d("loaded realms",realms);
	}
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Assert.hasText(username,"Usernam can't be empty");
		username = RealmUtil.normalize(username);
		loadRealms();
		if (realms == null) return null;
		for (Map.Entry<String, Realm> realm : realms.entrySet()) {
			try {
				if (realm.getValue().isEnabled() && realm.getValue() instanceof UserRealm) {
					User user = ((UserRealm)realm.getValue()).getUser(username);
					if (user != null) {
						log().d("load user {1} from realm {2}",username,realm.getKey());
						return user;
					}
				}
			} catch (Throwable t) {
				log().w("can't load user from realm {1}", realm.getKey(), t);
			}
		}
		throw new UsernameNotFoundException("user not found " + username);
	}
	
	public Acl loadAclForUsername(String username) {
		if (!StringUtils.hasText(username)) return null;
		username = RealmUtil.normalize(username);
		loadRealms();
		if (realms == null) return null;
		for (Map.Entry<String, Realm> realm : realms.entrySet()) {
			try {
				if (realm.getValue().isEnabled() && realm.getValue() instanceof UserAclRealm) {
					Acl acl = ((UserAclRealm)realm.getValue()).getAclForUser(username);
					if (acl != null) {
						log().d("load acl for user {1} from realm {2}",username,realm.getKey());
						return acl;
					}
				}
			} catch (Throwable t) {
				log().w("can't load acl from realm {1}", realm.getKey(), t);
			}
		}
		return null;
	}
	
	public Role loadRoleByRolename(String rolename) {
		if (!StringUtils.hasText(rolename)) return null;
		rolename = RealmUtil.normalize(rolename);
		loadRealms();
		if (realms == null) return null;
		for (Map.Entry<String, Realm> realm : realms.entrySet()) {
			try {
				if (realm.getValue().isEnabled() && realm.getValue() instanceof RoleRealm) {
					Role role = ((RoleRealm)realm.getValue()).getRole(rolename);
					if (role != null) {
						log().d("load role {1} from realm {2}",rolename,realm.getKey());
						return role;
					}
				}
			} catch (Throwable t) {
				log().w("can't load acl from realm {1}", realm.getKey(), t);
			}
		}
		return null;
	}
	
	public Acl loadAclForRole(String rolename) {
		if (!StringUtils.hasText(rolename)) return null;
		rolename = RealmUtil.normalize(rolename);
		loadRealms();
		if (realms == null) return null;
		for (Map.Entry<String, Realm> realm : realms.entrySet()) {
			try {
				if (realm.getValue().isEnabled() && realm.getValue() instanceof RoleAclRealm) {
					Acl acl = ((RoleAclRealm)realm.getValue()).getAclforRole(rolename);
					if (acl != null) {
						log().d("load acl for role {1} from realm {2}",rolename,realm.getKey());
						return acl;
					}
				}
			} catch (Throwable t) {
				log().w("can't load acl from realm {1}", realm.getKey(), t);
			}
		}
		return null;
	}

	public Set<String> loadRolesByUsername(String username) {
		if (!StringUtils.hasText(username)) return null;
		username = RealmUtil.normalize(username);
		loadRealms();
		if (realms == null) return null;
		for (Map.Entry<String, Realm> realm : realms.entrySet()) {
			try {
				if (realm.getValue().isEnabled() && realm.getValue() instanceof UserRoleRealm) {
					Set<String> roles = ((UserRoleRealm)realm.getValue()).getRolesForUser(username);
					if (roles != null) {
						log().d("load roles for user {1} from realm {2}",username,realm.getKey());
						return roles;
					}
				}
			} catch (Throwable t) {
				log().w("can't load roles from realm {1}", realm.getKey(), t);
			}
		}
		return null;
	}
	
}
