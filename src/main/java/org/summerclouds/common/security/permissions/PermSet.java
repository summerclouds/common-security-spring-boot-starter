package org.summerclouds.common.security.permissions;

import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.summerclouds.common.core.tool.MSecurity;
import org.summerclouds.common.core.tool.MString;
import org.summerclouds.common.core.tool.MSystem;

public class PermSet implements Iterable<Perm>, Permissions {

	private static final long serialVersionUID = 1L;
	public static final String PERMISSION_DIVIDER = ";";
	private boolean fullWildcard = false;
	private Set<Perm> permissions = new TreeSet<>(new Comparator<Perm>() {

		@Override
		public int compare(Perm o1, Perm o2) {
			int ret = o1.getObjectClass().compareTo(o2.getObjectClass());
			if (ret != 0) return ret;
			ret = o1.getActions().compareTo(o2.getActions());
			if (ret != 0) return ret;
			ret = o1.getObjectInstances().compareTo(o2.getObjectInstances());
			return ret;
		}
	});
	private Map<String,Actions> clazzes = new HashMap<>();

	public PermSet() {}
	
	public PermSet(String ... permissions) {
		for (String perm : permissions)
			for (String perm2 : perm.split(PERMISSION_DIVIDER))
				if (MString.isSetTrim(perm2))
					add(new Perm(perm2));
	}
	
	public PermSet(Collection<String> permissions) {
		for (String perm : permissions)
			for (String perm2 : perm.split(PERMISSION_DIVIDER))
				if (MString.isSetTrim(perm2))
					add(new Perm(perm2));
	}
	
	protected void add(Perm perm) {
		
		if (!permissions.add(perm))
			return; // already added - maybe with different comment
		
		if (fullWildcard) return;
		
		if (perm.isFullWildcard()) {
			fullWildcard  = true;
			clazzes.clear();
			return;
		}
		
		Actions actionMap = clazzes.get(perm.getObjectClass());
		if (actionMap == null) {
			actionMap = new Actions();
			clazzes.put(perm.getObjectClass(), actionMap);
		}
		for (String action : perm.getActions()) {
			Instances instanceSet = actionMap.get(action);
			if (instanceSet == null) {
				instanceSet = new Instances();
				actionMap.put(action, instanceSet);
			}
			for (String instance : perm.getObjectInstances())
				instanceSet.add(instance);
		}
		
	}
	
	public String toString() {
		return MSystem.toString(this,fullWildcard,clazzes);
	}
	
	@Override
	public String getAuthority() {
		return MString.join(permissions.iterator(), PERMISSION_DIVIDER);
	}

	public boolean hasPermission(Ace testify) {
		
		if (fullWildcard) return true;
		
		if (!testify.getObjectClass().equals(MSecurity.WILDCARD_TOKEN)) {
			Actions actions = clazzes.get(testify.getObjectClass());
			if (actions != null && actions.hasPermission(testify))
				return true;
			actions = clazzes.get(MSecurity.WILDCARD_TOKEN);
			if (actions != null) 
				return actions.hasPermission(testify);
		} else {
			// distinct wildcard
			for (Actions actions : clazzes.values()) {
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
			
			if (!action.equals(MSecurity.WILDCARD_TOKEN)) {
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
			if (action.equals(MSecurity.WILDCARD_TOKEN)) {
				if (wildcard == null)
					wildcard = instances;
				return;
			}
			if (action.endsWith(MSecurity.WILDCARD_TOKEN) && action.length() > MSecurity.WILDCARD_TOKEN.length()) {
				wildcards.put(action.substring(0,action.length()-MSecurity.WILDCARD_TOKEN.length()), instances);
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
			if (instance.equals(MSecurity.WILDCARD_TOKEN)) {
				wildcard = true;
				return;
			}
			if (instance.endsWith(MSecurity.WILDCARD_TOKEN) && instance.length() > MSecurity.WILDCARD_TOKEN.length()) {
				wildcards.add(instance.substring(0,instance.length()-MSecurity.WILDCARD_TOKEN.length()));
			}
		}

		public boolean hasPermission(Ace perm) {
			String instance = perm.getInstance();
			if (instance == null) return false;
			if (instance.equals(MSecurity.WILDCARD_TOKEN) && entries.size() > 0) return true;
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
	public Iterator<Perm> iterator() {
		return permissions.iterator();
	}
}
