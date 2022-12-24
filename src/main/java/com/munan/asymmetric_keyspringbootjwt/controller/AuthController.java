package com.munan.asymmetric_keyspringbootjwt.controller;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

import static java.time.temporal.ChronoUnit.MINUTES;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtEncoder encoder;

    public AuthController(AuthenticationManager authenticationManager, JwtEncoder encoder) {
        this.authenticationManager = authenticationManager;
        this.encoder = encoder;
    }

    @PostMapping("/token/{username}/{password}")
    public String generateToken(@PathVariable("username")String username, @PathVariable("password")String password){

        Authentication authentication = authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(username,password)
        );
        Instant now = Instant.now();
        List<String> scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(20, MINUTES))
                .subject(authentication.getName())
                .claim("scope", scope)
                .build();

        return this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}
