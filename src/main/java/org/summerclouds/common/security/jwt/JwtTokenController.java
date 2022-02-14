package org.summerclouds.common.security.jwt;

import java.util.Date;
import java.util.HashMap;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.summerclouds.common.core.tool.MPeriod;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@RestController
public class JwtTokenController {

	private long maxTimeout = MPeriod.HOUR_IN_MILLISECONDS;
	private long defaultTimeout = MPeriod.HOUR_IN_MILLISECONDS;
    private String secret = "abc123";


	@PostMapping("/jwt_token")
	public TokenResponse createToken(@RequestParam(value = "timeout", defaultValue = "0") long timeout) {
		if (timeout <= 0 || timeout > maxTimeout )
			timeout = defaultTimeout;
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !authentication.isAuthenticated())
			throw new ResponseStatusException(HttpStatus.FORBIDDEN);
		
		String currentPrincipalName = authentication.getName();
		String token = generateToken(currentPrincipalName, timeout);
		return new TokenResponse(currentPrincipalName, timeout, token);
	}

    public String generateToken(String username, long timeout) {
        final Date createdDate = new Date();
        final Date expirationDate = calculateExpirationDate(createdDate, timeout);

        return Jwts.builder()
                .setClaims(new HashMap<>())
                .setSubject(username)
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    private Date calculateExpirationDate(Date createdDate, long timeout) {
        return new Date(createdDate.getTime() + timeout);
    }

}
