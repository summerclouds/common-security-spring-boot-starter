package org.summerclouds.common.security.permissions;

import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.summerclouds.common.core.tool.MString;
import org.summerclouds.common.core.tool.MSystem;

public class Acl implements PermissionSet, Iterable<WildcardAce> {

	private static final long serialVersionUID = 1L;
	public static final String PERMISSION_DIVIDER = ";";
	private boolean fullWildcard = false;
	private Set<WildcardAce> permissions = new TreeSet<>(new Comparator<WildcardAce>() {

		@Override
		public int compare(WildcardAce o1, WildcardAce o2) {
			int ret = o1.getObject().compareTo(o2.getObject());
			if (ret != 0) return ret;
			ret = o1.getActions().compareTo(o2.getActions());
			if (ret != 0) return ret;
			ret = o1.getInstances().compareTo(o2.getInstances());
			return ret;
		}
	});
	private Map<String,Actions> objects = new HashMap<>();

	public Acl() {}
	
	public Acl(String ... permissions) {
		for (String perm : permissions)
			for (String perm2 : perm.split(PERMISSION_DIVIDER))
				if (MString.isSetTrim(perm2))
					add(new WildcardAce(perm2));
	}
	
	public Acl(Collection<String> permissions) {
		for (String perm : permissions)
			for (String perm2 : perm.split(PERMISSION_DIVIDER))
				if (MString.isSetTrim(perm2))
					add(new WildcardAce(perm2));
	}
	
	protected void add(WildcardAce perm) {
		
		if (!permissions.add(perm))
			return; // already added - maybe with different comment
		
		if (fullWildcard) return;
		
		if (perm.isFullWildcard()) {
			fullWildcard  = true;
			objects.clear();
			return;
		}
		
		Actions actionMap = objects.get(perm.getObject());
		if (actionMap == null) {
			actionMap = new Actions();
			objects.put(perm.getObject(), actionMap);
		}
		for (String action : perm.getActions()) {
			Instances instanceSet = actionMap.get(action);
			if (instanceSet == null) {
				instanceSet = new Instances();
				actionMap.put(action, instanceSet);
			}
			for (String instance : perm.getInstances())
				instanceSet.add(instance);
		}
		
	}
	
	public String toString() {
		return MSystem.toString(this,fullWildcard,objects);
	}
	
	@Override
	public String getAuthority() {
		return MString.join(permissions.iterator(), PERMISSION_DIVIDER);
	}

	public boolean hasPermission(Ace testify) {
		
		if (fullWildcard) return true;
		
		if (!testify.getObject().equals(Ace.WILDCARD_TOKEN)) {
			Actions actions = objects.get(testify.getObject());
			if (actions != null && actions.hasPermission(testify))
				return true;
			actions = objects.get(Ace.WILDCARD_TOKEN);
			if (actions != null) 
				return actions.hasPermission(testify);
		} else {
			// distinct wildcard
			for (Actions actions : objects.values()) {
				return actions.hasPermission(testify);
			}
		}
		return false;
	}

	protected Set<String> getInstanceSet(Map<String, Set<String>> actionMap, String action) {
		return actionMap.get(action);
	}

	public boolean isFullWildcard() {
		return fullWildcard;
	}

	@Override
	public boolean hasPermission(String perm) {
		return hasPermission(new Ace(perm));
	}
	
	private class Actions {
		
		private Map<String, Instances> entries = new HashMap<>();
		private Map<String, Instances> wildcards = new HashMap<>();
		private Instances wildcard;
		
		public Instances get(String action) {
			return entries.get(action);
		}

		public boolean hasPermission(Ace perm) {
			String action = perm.getAction();
			if (action == null) return false;
			
			if (wildcard != null)
				if (wildcard.hasPermission(perm)) return true;
			
			if (!action.equals(Ace.WILDCARD_TOKEN)) {
				Instances res = entries.get(action);
				if (res != null && res.hasPermission(perm)) return true;
				for (Map.Entry<String, Instances> value : wildcards.entrySet())
					if (action.startsWith(value.getKey()) && 
						value.getValue().hasPermission(perm))
							return true;
			} else {
				// distinct action wildcard
				for (Instances res : entries.values()) {
					if (res.hasPermission(perm)) return true;
					for (Map.Entry<String, Instances> value : wildcards.entrySet())
						if (action.startsWith(value.getKey()) && 
							value.getValue().hasPermission(perm))
								return true;
				}
			}
			return false;
		}

		public void put(String action, Instances instances) {
			entries.put(action, instances);
			if (action.equals(Ace.WILDCARD_TOKEN)) {
				if (wildcard == null)
					wildcard = instances;
				return;
			}
			if (action.endsWith(Ace.WILDCARD_TOKEN) && action.length() > Ace.WILDCARD_TOKEN.length()) {
				wildcards.put(action.substring(0,action.length()-Ace.WILDCARD_TOKEN.length()), instances);
			}
		}
		
		@Override
		public String toString() {
			return MSystem.toString(this, entries);
		}
		
	}
	
	private class Instances {
		
		private Set<String> entries = new HashSet<>();
		private Set<String> wildcards = new HashSet<>();
		private boolean wildcard = false;
		
		public void add(String instance) {
			entries.add(instance);
			if (instance.equals(Ace.WILDCARD_TOKEN)) {
				wildcard = true;
				return;
			}
			if (instance.endsWith(Ace.WILDCARD_TOKEN) && instance.length() > Ace.WILDCARD_TOKEN.length()) {
				wildcards.add(instance.substring(0,instance.length()-Ace.WILDCARD_TOKEN.length()));
			}
		}

		public boolean hasPermission(Ace perm) {
			String instance = perm.getInstance();
			if (instance == null) return false;
			if (instance.equals(Ace.WILDCARD_TOKEN) && entries.size() > 0) return true;
			if (wildcard || entries.contains(instance)) return true;
			for (String value : wildcards)
				if (instance.startsWith(value))
					return true;
			return false;
		}
		
		@Override
		public String toString() {
			return MSystem.toString(this, entries);
		}
		
	}

	@Override
	public Iterator<WildcardAce> iterator() {
		return permissions.iterator();
	}
}
