package com.litmus7.river;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = "com.litmus7.river")
public class GoogleLoginApplication {

    public static void main(String[] args) {
        SpringApplication.run(GoogleLoginApplication.class);
    }
}
