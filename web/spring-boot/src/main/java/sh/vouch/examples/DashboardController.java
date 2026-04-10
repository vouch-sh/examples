package sh.vouch.examples;

import java.util.Base64;
import java.util.Map;
import org.springframework.boot.json.JsonParserFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

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

        // Hardware claims are in the access token JWT (RFC 9068), not the id_token.
        boolean hardwareVerified = false;
        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        String[] parts = accessToken.split("\\.");
        if (parts.length == 3) {
            try {
                String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                Map<String, Object> claims = JsonParserFactory.getJsonParser().parseMap(payload);
                hardwareVerified = Boolean.TRUE.equals(claims.get("hardware_verified"));
            } catch (Exception ignored) {
            }
        }
        model.addAttribute("hardwareVerified", hardwareVerified);
        return "dashboard";
    }
}
