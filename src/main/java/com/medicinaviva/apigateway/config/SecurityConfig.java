package com.medicinaviva.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import com.medicinaviva.apigateway.helpers.JWTConverter;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain config(ServerHttpSecurity http){
               http
                .csrf(crsf -> crsf.disable())
                .authorizeExchange(exchange -> exchange 
                    .pathMatchers("/api/**")
                    .authenticated()
                    .anyExchange()
                    .permitAll())
                    .oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(jwt -> jwt.jwtAuthenticationConverter(new JWTConverter())));
                    
                return http.build();
    }
}
