package org.summerclouds.common.security.internal;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.summerclouds.common.core.crypt.IPasswordEncoder;

@Configuration
@ConfigurationProperties(prefix = "org.summerclouds.common.core")
public class SpringSummerCloudsSecurityAutoConfiguration {

	@Bean(name = "bcrypt")
	public IPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptIPasswordEncoder();
	}
	
}
