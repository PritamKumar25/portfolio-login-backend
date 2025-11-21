package com.portfolio.login;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
public class LoginApplication {

	public static void main(String[] args) {

		SpringApplication.run(LoginApplication.class, args);
		System.out.println("mysupersecretkeyisverysecureformyportfolioapplication".length());
	}

}
