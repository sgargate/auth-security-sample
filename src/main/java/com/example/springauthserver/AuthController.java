package com.example.springauthserver;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.joining;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.ResponseEntity.ok;
import static org.springframework.security.web.util.UrlUtils.buildFullRequestUrl;
import static org.springframework.web.util.UriComponentsBuilder.fromHttpUrl;

@RestController
@RequestMapping(path = "/api/public")
public class AuthController {
  public AuthController(AuthenticationManager authenticationManager, JwtEncoder jwtEncoder, RegisteredClientRepository registeredClientRepository) {
    this.authenticationManager = authenticationManager;
    this.jwtEncoder = jwtEncoder;
    this.registeredClientRepository = registeredClientRepository;
  }

  private final AuthenticationManager authenticationManager;
  private final JwtEncoder jwtEncoder;
  private final RegisteredClientRepository registeredClientRepository;

  @PostMapping("/login")
  public ResponseEntity<UserView> login(@RequestBody AuthRequest request,
                                        @RequestHeader("client_id") String clientId,
                                        HttpServletRequest httpRequest
                                        ) {
    try {
      var authentication =
          authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(request.email(), request.password()));

      User user = (User) authentication.getPrincipal();

      var now = Instant.now();

      RegisteredClient client = registeredClientRepository.findByClientId(clientId);
      var scope =
          authentication.getAuthorities().stream()
              .map(GrantedAuthority::getAuthority)
              .collect(joining(" "));

      var claims =
          JwtClaimsSet.builder()
                  .audience(singletonList(client.getClientId()))
              .issuer(issuer(httpRequest))
              .issuedAt(now)
              .expiresAt(now.plus(client.getTokenSettings().getAccessTokenTimeToLive()))
              .subject(user.getUsername())
              .claim("roles", scope)
              .build();

      var token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

      return ok()
          .header(AUTHORIZATION, token)
          .body(new UserView(user.getUsername()));
    } catch (BadCredentialsException ex) {
      return ResponseEntity.status(UNAUTHORIZED).build();
    }
  }

  private static String issuer(HttpServletRequest httpRequest) {
    return fromHttpUrl(buildFullRequestUrl(httpRequest))
            .replacePath(httpRequest.getContextPath()).build().toUriString();
  }
}

class UserView{
  private String id;

  public UserView(String id) {
    this.id = id;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }
}