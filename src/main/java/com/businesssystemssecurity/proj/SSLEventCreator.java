package com.businesssystemssecurity.proj;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableScheduling
@Component
@EnableAsync
public class SSLEventCreator {

    @Autowired
    private RestTemplate restTemplate;

    private boolean systemReady = false;

    @Async
    @Scheduled(initialDelay = 1000 * 5, fixedDelay = 1000 * 10)
    public void create() {

        if (!this.systemReady) {
            return;
        }

        try {
            String responseFromSub = restTemplate.getForObject("https://localhost:8444/api/testSSL/receiveFromSub", String.class);
            System.out.println("----> Response from sub: " + responseFromSub);

        } catch (Exception e) {
            //e.printStackTrace();
            System.out.println("Fatal error.");
        }
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        this.systemReady = true;
    }
}