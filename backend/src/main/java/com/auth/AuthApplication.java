package com.auth;

import com.auth.models.File;
import com.auth.repository.FileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

}
