package dev.chux.idp.oidc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class OidcServer {

	public static void main(String[] args) {
		SpringApplication.run(OidcServer.class, args);
	}

}
