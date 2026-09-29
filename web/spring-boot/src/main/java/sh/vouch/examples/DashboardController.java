package sh.vouch.examples;

import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    private final JwtDecoder accessTokenDecoder;

    public DashboardController(JwtDecoder accessTokenDecoder) {
        this.accessTokenDecoder = accessTokenDecoder;
    }

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/dashboard")
    public String dashboard(
            @AuthenticationPrincipal OidcUser user,
            @RegisteredOAuth2AuthorizedClient("vouch") OAuth2AuthorizedClient authorizedClient,
            Model model) {
        model.addAttribute("email", user.getEmail());
        model.addAttribute("emailVerified", Boolean.TRUE.equals(user.getEmailVerified()));
        model.addAttribute("sub", user.getSubject());
        model.addAttribute("acr", user.getIdToken().getAuthenticationContextClass());
        model.addAttribute("amr", user.getIdToken().getAuthenticationMethods());

        // hardware_verified is only in the access token, not the id_token. Verify it
        // rather than decoding the payload; a failure here means the token is not
        // trustworthy, so let it propagate instead of quietly showing "not verified".
        Jwt accessToken = accessTokenDecoder.decode(
                authorizedClient.getAccessToken().getTokenValue());
        model.addAttribute("hardwareVerified",
                Boolean.TRUE.equals(accessToken.getClaim("hardware_verified")));
        // Thumbprint of the DPoP key the access token is bound to (RFC 9449 section 6).
        Map<String, Object> cnf = accessToken.getClaimAsMap("cnf");
        model.addAttribute("cnfJkt", cnf == null ? null : cnf.get("jkt"));
        return "dashboard";
    }
}
