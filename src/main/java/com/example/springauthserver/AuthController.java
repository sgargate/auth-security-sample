package com.example.springauthserver;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

import static java.util.stream.Collectors.joining;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.ResponseEntity.ok;

@RestController
@RequestMapping(path = "/api/public")
public class AuthController {
  public AuthController(AuthenticationManager authenticationManager, JwtEncoder jwtEncoder) {
    this.authenticationManager = authenticationManager;
    this.jwtEncoder = jwtEncoder;
  }

  private final AuthenticationManager authenticationManager;
  private final JwtEncoder jwtEncoder;

  @PostMapping("/login")
  public ResponseEntity<UserView> login(@RequestBody AuthRequest request) {
    try {
      var authentication =
          authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(request.email(), request.password()));

      User user = (User) authentication.getPrincipal();

      var now = Instant.now();
      var expiry = 36000L;

      var scope =
          authentication.getAuthorities().stream()
              .map(GrantedAuthority::getAuthority)
              .collect(joining(" "));

      var claims =
          JwtClaimsSet.builder()
              .issuer("example.io")
              .issuedAt(now)
              .expiresAt(now.plusSeconds(expiry))
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