package sh.vouch.examples;

import java.net.URI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
            ClientRegistrationRepository clientRegistrationRepository,
            DPoPInterceptor dpop) throws Exception {
        DefaultOAuth2AuthorizationRequestResolver resolver =
            new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
        resolver.setAuthorizationRequestCustomizer(
            OAuth2AuthorizationRequestCustomizers.withPkce());

        // Signing out locally is not enough: the user stays signed in at Vouch, so the
        // next sign-in would complete silently. This handler redirects to Vouch's
        // end_session_endpoint (from discovery) with the ID token as id_token_hint.
        // Vouch only redirects back when the hint verifies and post_logout_redirect_uri
        // exactly matches one registered on the client.
        OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler =
            new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        // Vouch compares post_logout_redirect_uri as an exact string, so derive it from
        // the registered redirect URI's origin rather than from the request's Host header.
        String redirectUri =
            clientRegistrationRepository.findByRegistrationId("vouch").getRedirectUri();
        logoutSuccessHandler.setPostLogoutRedirectUri(
            URI.create(redirectUri).resolve("/").toString());

        // DPoP-bound access tokens (RFC 9449). The token client and the UserInfo client are
        // Spring's defaults, rebuilt with the same converters and error handlers plus the
        // DPoP interceptor.
        RestClientAuthorizationCodeTokenResponseClient tokenClient =
            new RestClientAuthorizationCodeTokenResponseClient();
        tokenClient.setRestClient(RestClient.builder()
            .configureMessageConverters(converters -> converters
                .addCustomConverter(new FormHttpMessageConverter())
                .addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter()))
            .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
            .requestInterceptor(dpop)
            .build());

        RestTemplate userInfoClient = new RestTemplate();
        userInfoClient.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        userInfoClient.getInterceptors().add(dpop);
        DefaultOAuth2UserService userInfoService = new DefaultOAuth2UserService();
        userInfoService.setRestOperations(userInfoClient);
        OidcUserService oidcUserService = new OidcUserService();
        oidcUserService.setOauth2UserService(userInfoService);

        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .defaultSuccessUrl("/dashboard", true)
                .authorizationEndpoint(authorization -> authorization
                    .authorizationRequestResolver(resolver)
                )
                .tokenEndpoint(token -> token.accessTokenResponseClient(tokenClient))
                .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService))
            )
            .logout(logout -> logout
                .logoutSuccessHandler(logoutSuccessHandler)
            );
        return http.build();
    }

}
