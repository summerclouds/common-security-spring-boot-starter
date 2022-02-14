package org.summerclouds.common.security.jwt;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String TOKEN_HEADER = "Authorization";

	private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/login",
			"POST");

	public JwtAuthenticationFilter() {
		super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
	}
	
	public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
		super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
        final String token = obtainToken(request);
        if (token == null) return null;
        
        
        JwtAuthenticationToken authRequest = new JwtAuthenticationToken(token);
        if (!authRequest.isTokenValid())
        	throw new AuthenticationServiceException("Authentication token is not valid");
//        if (!authRequest.isTokenNotExpired())
//        	throw new AuthenticationServiceException("Authentication token expired");

        setDetails(request, authRequest);
		return this.getAuthenticationManager().authenticate(authRequest);
	}

	@Nullable
	protected String obtainToken(HttpServletRequest request) {
		final String requestHeader = request.getHeader(TOKEN_HEADER);
        if (requestHeader != null && requestHeader.startsWith("Bearer ")) {
            return requestHeader.substring(7);
        }
        return null;
	}

	protected void setDetails(HttpServletRequest request, JwtAuthenticationToken authRequest) {
		authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
	}

}
