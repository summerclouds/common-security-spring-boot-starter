package org.summerclouds.common.security.internal;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.summerclouds.common.core.crypt.IPasswordEncoder;
import org.summerclouds.common.core.error.NotSupportedException;

public class BCryptIPasswordEncoder implements IPasswordEncoder {

	private PasswordEncoder encoder = new BCryptPasswordEncoder();
	
	@Override
	public String encode(String plain, String secret) {
		return encoder.encode(plain);
	}

	@Override
	public String decode(String encoded, String secret) {
		throw new NotSupportedException("decode not supported for bcrypt");
	}

	@Override
	public boolean validate(String plain, String encoded, String secret) {
		return encoder.matches(plain, encoded);
	}

}
