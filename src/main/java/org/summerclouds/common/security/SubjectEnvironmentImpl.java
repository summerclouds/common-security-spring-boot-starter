package org.summerclouds.common.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.summerclouds.common.core.security.ISubject;
import org.summerclouds.common.core.security.ISubjectEnvironment;

public class SubjectEnvironmentImpl implements ISubjectEnvironment {

	private Authentication previous;
	private SubjectImpl subject;

	public SubjectEnvironmentImpl(Authentication auth) {
		previous = SecurityContextHolder.getContext().getAuthentication();
		SecurityContextHolder.getContext().setAuthentication(auth);
		Object user = auth.getPrincipal();
		subject = new SubjectImpl((User)user, auth);
	}

	@Override
	public ISubject getSubject() {
		return subject;
	}

	@Override
	public void close() {
		SecurityContextHolder.getContext().setAuthentication(previous);
	}

}
