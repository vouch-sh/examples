package sh.vouch.examples;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import java.io.IOException;
import java.net.URI;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;

/**
 * Adds DPoP proofs (RFC 9449) to requests sent to Vouch.
 *
 * <p>Spring Security's OAuth 2.0 client has no client-side DPoP, so this interceptor is
 * installed on the token client and on the UserInfo client (see SecurityConfig). The key
 * pair lives for the process: the confidential client, not the browser, holds the token.
 *
 * <p>On the token request it only adds a proof. On any request that carries an access
 * token it also switches the Authorization scheme to DPoP and binds the proof to the token
 * with {@code ath}; Vouch rejects a DPoP-bound token presented as Bearer.
 *
 * <p>Vouch's token endpoint always answers the first attempt with {@code use_dpop_nonce}
 * and a {@code DPoP-Nonce} header, so a 400 or 401 carrying that header is retried once
 * with the nonce, and the latest nonce is sent up front on later requests.
 */
@Component
public class DPoPInterceptor implements ClientHttpRequestInterceptor {

    private static final String DPOP_NONCE = "DPoP-Nonce";

    private final DPoPProofFactory proofFactory;
    private final AtomicReference<String> nonce = new AtomicReference<>();

    public DPoPInterceptor() throws JOSEException {
        ECKey key = new ECKeyGenerator(Curve.P_256).generate();
        this.proofFactory = new DefaultDPoPProofFactory(key, JWSAlgorithm.ES256);
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body,
            ClientHttpRequestExecution execution) throws IOException {
        String accessToken = accessToken(request.getHeaders());
        if (accessToken != null) {
            request.getHeaders().set(HttpHeaders.AUTHORIZATION, "DPoP " + accessToken);
        }

        request.getHeaders().set("DPoP", proof(request, accessToken, nonce.get()));
        ClientHttpResponse response = execution.execute(request, body);
        String issuedNonce = response.getHeaders().getFirst(DPOP_NONCE);
        if (issuedNonce == null) {
            return response;
        }
        nonce.set(issuedNonce);

        HttpStatus status = HttpStatus.resolve(response.getStatusCode().value());
        if (status != HttpStatus.BAD_REQUEST && status != HttpStatus.UNAUTHORIZED) {
            return response;
        }
        response.close();
        request.getHeaders().set("DPoP", proof(request, accessToken, issuedNonce));
        return execution.execute(request, body);
    }

    private String proof(HttpRequest request, String accessToken, String currentNonce)
            throws IOException {
        URI uri = request.getURI();
        // htu excludes the query and fragment (RFC 9449 section 4.2).
        URI htu = URI.create(uri.getScheme() + "://" + uri.getRawAuthority() + uri.getRawPath());
        Nonce proofNonce = currentNonce == null ? null : new Nonce(currentNonce);
        try {
            return (accessToken == null
                    ? proofFactory.createDPoPJWT(request.getMethod().name(), htu, proofNonce)
                    : proofFactory.createDPoPJWT(request.getMethod().name(), htu,
                            new DPoPAccessToken(accessToken), proofNonce))
                    .serialize();
        } catch (JOSEException e) {
            throw new IOException("Could not sign DPoP proof", e);
        }
    }

    private static String accessToken(HttpHeaders headers) {
        String authorization = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null) {
            return null;
        }
        for (String scheme : new String[] {"Bearer ", "DPoP "}) {
            if (authorization.regionMatches(true, 0, scheme, 0, scheme.length())) {
                return authorization.substring(scheme.length());
            }
        }
        // Basic client authentication on the token request, not an access token.
        return null;
    }
}
