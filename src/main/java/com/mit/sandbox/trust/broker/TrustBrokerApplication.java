package com.mit.sandbox.trust.broker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@ConfigurationPropertiesScan
@SpringBootApplication
public class TrustBrokerApplication {

    static void main(String[] args) {
        SpringApplication.run(TrustBrokerApplication.class, args);
    }
}