package org.summerclouds.common.security.internal;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.summerclouds.common.core.crypt.IPasswordEncoder;
import org.summerclouds.common.core.security.ISecurity;
import org.summerclouds.common.security.SecurityService;

@Configuration
@ConfigurationProperties(prefix = "org.summerclouds.common.core")
public class SpringSummerCloudsSecurityAutoConfiguration {

	@Bean(name = "bcrypt")
	public IPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptIPasswordEncoder();
	}
	
    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ISecurity security() {
    	return new SecurityService();
    }

}
