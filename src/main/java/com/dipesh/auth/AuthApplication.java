package com.dipesh.auth;

import io.jsonwebtoken.Claims;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@SpringBootApplication
public class AuthApplication {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {

		String key = GenerateKey.createJWT("1", "sikkerhet-intern.helsenorge.no","Dipesh");
		Claims claim = GenerateKey.decodeJWT(key);
		SpringApplication.run(AuthApplication.class, args);
	}

}
