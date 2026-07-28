package sh.vouch.examples;

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

        // hardware_verified is only in the access token, not the id_token. Verify it
        // rather than decoding the payload; a failure here means the token is not
        // trustworthy, so let it propagate instead of quietly showing "not verified".
        Jwt accessToken = accessTokenDecoder.decode(
                authorizedClient.getAccessToken().getTokenValue());
        model.addAttribute("hardwareVerified",
                Boolean.TRUE.equals(accessToken.getClaim("hardware_verified")));
        model.addAttribute("acr", accessToken.getClaimAsString("acr"));
        model.addAttribute("amr", accessToken.getClaimAsStringList("amr"));
        return "dashboard";
    }
}
