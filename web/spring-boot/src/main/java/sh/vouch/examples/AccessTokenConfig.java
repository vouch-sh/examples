package sh.vouch.examples;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

/**
 * Decoder for Vouch access tokens.
 *
 * <p>hardware_verified is only in the access token, not the id_token. The access token is
 * an ES256-signed RFC 9068 JWT, so verify it against the published JWKS rather than
 * decoding the payload -- an unverified decode trusts whatever bytes you were handed.
 */
@Configuration
public class AccessTokenConfig {

    /** RFC 9068 access tokens use this JOSE type, which distinguishes them from id_tokens. */
    private static final JOSEObjectType AT_JWT = new JOSEObjectType("at+jwt");

    @Bean
    public JwtDecoder accessTokenDecoder(
            @Value("${spring.security.oauth2.client.provider.vouch.issuer-uri}") String issuer,
            @Value("${spring.security.oauth2.client.registration.vouch.client-id}") String clientId) {

        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withJwkSetUri(issuer + "/oauth/jwks")
                // withJwkSetUri defaults to RS256 only. Vouch signs access tokens with
                // ES256, which would otherwise fail as "no matching key(s) found".
                .jwsAlgorithms(algorithms -> {
                    algorithms.add(SignatureAlgorithm.ES256);
                    algorithms.add(SignatureAlgorithm.RS256);
                })
                // Spring's default type verifier accepts only "JWT" or an absent typ, so
                // an RFC 9068 token would be rejected out of hand. Requiring at+jwt here
                // both fixes that and rejects id_tokens, which are not bearer credentials.
                .jwtProcessorCustomizer(p -> p.setJWSTypeVerifier(
                        new DefaultJOSEObjectTypeVerifier<>(AT_JWT)))
                .build();

        // The audience is this client's own client_id, which is what Vouch issues when
        // the authorization request carries no RFC 8707 resource parameter.
        OAuth2TokenValidator<Jwt> audience = new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD, aud -> aud != null && aud.contains(clientId));

        // Built explicitly rather than via JwtValidators.createDefaultWithIssuer, whose
        // chain includes a JwtTypeValidator that insists on typ=JWT and so rejects every
        // RFC 9068 access token.
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtIssuerValidator(issuer),
                new JwtTimestampValidator(),
                audience));
        return decoder;
    }
}
