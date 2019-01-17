/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.revo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.gateway.config.GatewayProperties;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;
import static org.springframework.web.reactive.function.server.ServerResponse.ok;

@SpringBootApplication
@EnableDiscoveryClient
@Slf4j
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    @Bean
    public RouterFunction<ServerResponse> indexRouter(GatewayProperties gatewayProperties, @Value("classpath:/static/index.html") final Resource indexHtml) {
        return route(serverRequest -> {
            boolean gateway = gatewayProperties.getRoutes().stream()
                    .flatMap(it -> it.getPredicates().stream())
                    .filter(it -> it.getName().equalsIgnoreCase("Path"))
                    .map(it -> it.getArgs().get("_genkey_0")).map(it -> new PathPatternParser().parse(it)).anyMatch(it -> it.matches(serverRequest.exchange().getRequest().getPath().pathWithinApplication()));
            return !gateway && !serverRequest.path().contains(".");
        }, request -> ok().contentType(MediaType.TEXT_HTML).syncBody(indexHtml));
    }

    @Bean
    public GlobalFilter filter(ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
        return (exchange, chain) -> exchange.getPrincipal()
                .cast(OAuth2AuthenticationToken.class)
                .flatMap(authentication -> authorizedClientRepository.loadAuthorizedClient(authentication.getAuthorizedClientRegistrationId(), authentication, exchange).cast(OAuth2AuthorizedClient.class))
                .map(OAuth2AuthorizedClient::getAccessToken)
                .map(token -> exchange.mutate().request(r -> r.headers(headers -> headers.setBearerAuth(token.getTokenValue()))).build())
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter)
                .then(Mono.fromRunnable(() -> {
                    String name = "Set-Cookie";
                    String value = exchange.getResponse().getHeaders().getFirst(name);
                    if (!new PathPatternParser().parse("/auth/**").matches(exchange.getRequest().getPath().pathWithinApplication()) && value != null) {
                        exchange.getResponse().getHeaders().set(name, value.replaceAll("JSESSIONID=[0-9a-zA-Z]+; ", ""));
                    }
                }));
    }

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange()
                .anyExchange().permitAll()
                .and().oauth2Login()
                .and().logout()
                .and().csrf().csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
                .requireCsrfProtectionMatcher(pathMatchers("/auth"))
                .and().build();
    }
}