package za.co.allegra.medscheme.user.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import za.co.allegra.medscheme.user.dto.ApplicationUser;
import za.co.allegra.medscheme.user.util.JwtTokenUtil;

import java.util.Base64;

@Service
@Slf4j
public class AuthenticationService {
    private AuthenticationManager authenticationManager;
    private JwtUserDetailsService userDetailsService;
    private JwtTokenUtil jwtTokenUtil;

    public AuthenticationService(AuthenticationManager authenticationManager, JwtUserDetailsService userDetailsService, JwtTokenUtil jwtTokenUtil) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    public String authenticateAndGetToken(String authorization) {
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
        return token;
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
