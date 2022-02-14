package org.summerclouds.common.security.jwt;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class JwtAuthenticationConverter implements AuthenticationConverter {

	public static final String AUTHENTICATION_SCHEME_BEARER = "Bearer ";

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	public JwtAuthenticationConverter() {
		this(new WebAuthenticationDetailsSource());
	}

	public JwtAuthenticationConverter(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
		return this.authenticationDetailsSource;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	@Override
	public JwtAuthenticationToken convert(HttpServletRequest request) {
		String header = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (header == null) {
			return null;
		}
		header = header.trim();
		if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BEARER)) {
			return null;
		}

		String token = header.substring(AUTHENTICATION_SCHEME_BEARER.length());

		JwtAuthenticationToken result = new JwtAuthenticationToken(token);
		result.setDetails(this.authenticationDetailsSource.buildDetails(request));
		return result;
	}

}