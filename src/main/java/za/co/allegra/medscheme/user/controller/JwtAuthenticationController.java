package za.co.allegra.medscheme.user.controller;

import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.ObjectUtils;
import org.jboss.aerogear.security.otp.Totp;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import za.co.allegra.medscheme.user.dto.ApplicationUser;
import za.co.allegra.medscheme.user.dto.Token;
import za.co.allegra.medscheme.user.service.JwtUserDetailsService;
import za.co.allegra.medscheme.user.util.JwtTokenUtil;

import javax.validation.Valid;
import java.security.Principal;
import java.util.Base64;

@RestController
@CrossOrigin
@Log4j2
public class JwtAuthenticationController {
    private AuthenticationManager authenticationManager;
    private JwtTokenUtil jwtTokenUtil;
    private JwtUserDetailsService userDetailsService;

    public JwtAuthenticationController(AuthenticationManager authenticationManager, JwtTokenUtil jwtTokenUtil, JwtUserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenUtil = jwtTokenUtil;
        this.userDetailsService = userDetailsService;
    }

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<Token> createAuthenticationToken(@RequestHeader(value = "Authorization", required = true) String authorization) {
        if (ObjectUtils.isNotEmpty(authorization) && authorization.contains("Basic ")) {
            byte[] decodedBytes = Base64.getDecoder().decode(authorization.replace("Basic ", ""));
            String decodedString = new String(decodedBytes);
            String username = decodedString.split(":")[0];
            String password = decodedString.split(":")[1];
            authenticate(username, password);
            ApplicationUser applicationUser = (ApplicationUser) userDetailsService.loadUserByUsername(username);
            String token;
            if (applicationUser.getMfaEnabled()) {
                token = jwtTokenUtil.generateTokenMFANotPassed(applicationUser);
            } else {
                token = jwtTokenUtil.generateTokenMFAPassedOrNotRequiredToken(applicationUser);
            }
            return ResponseEntity.ok(new Token(token));
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    @RequestMapping(value = "/authenticate/mfa", method = RequestMethod.POST)
    @PreAuthorize("hasAuthority('PRE_AUTHENTICATED_MFA_REQUIRED')")
    public ResponseEntity<String> createAuthenticationTokenWithMFA(@RequestBody @Valid Mfa mfa, Principal principal) {
        log.info("Secret: " + ((ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal()).getMfaSecret());
        Totp totp = new Totp(((ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal()).getMfaSecret());
        log.info("Verify:" + totp.verify(mfa.getMfaCode()));
        log.info("Verify:" + totp.now());
        return ResponseEntity.ok(totp.now());
    }

    private void authenticate(String username, String password) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (AuthenticationException e) {
            log.info("Exception with authentication: " + e.getLocalizedMessage());
            throw e;
        }
    }
}