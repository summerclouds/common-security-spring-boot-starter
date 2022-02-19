package org.summerclouds.common.security.realm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.summerclouds.common.security.permissions.PermSet;

public class MemoryUserRealm extends AbstractUserRealm {

	@Autowired
	private PasswordEncoder encoder;
	
	private HashMap<String,String> users = new HashMap<>();
	
	@Override
	public boolean isEnabled() {
		return !users.isEmpty();
	}

	@Override
	protected User createUser(String username, PermSet acl, Map<String, String> data) {
		String password = users.get(username);
		if (password == null) return null;
		ArrayList<GrantedAuthority> list = new ArrayList<>(1);
		list.add(acl);
		return new DataUser(username, encoder.encode(password), list, data);
	}

	public MemoryUserRealm add(String name, String password) {
		users.put(name, password);
		return this;
	}

}
