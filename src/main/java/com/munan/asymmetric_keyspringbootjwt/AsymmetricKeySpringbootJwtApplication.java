package com.munan.asymmetric_keyspringbootjwt;

import com.munan.asymmetric_keyspringbootjwt.security.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeyProperties.class)
public class AsymmetricKeySpringbootJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(AsymmetricKeySpringbootJwtApplication.class, args);
	}

}
