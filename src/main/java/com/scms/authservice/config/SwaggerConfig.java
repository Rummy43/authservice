package com.scms.authservice.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Value("${keycloak.token-url}")
    private String tokenUrl;

    @Bean
    public OpenAPI customOpenAPI() {
        SecurityScheme oauth2Scheme = new SecurityScheme()
                .type(SecurityScheme.Type.OAUTH2)
                .flows(new OAuthFlows().password(
                        new OAuthFlow()
                                .tokenUrl(tokenUrl)
                                .scopes(null)
                ));

        return new OpenAPI()
                .components(new Components().addSecuritySchemes("oauth2", oauth2Scheme))
                .addSecurityItem(new SecurityRequirement().addList("oauth2"));
    }
}


