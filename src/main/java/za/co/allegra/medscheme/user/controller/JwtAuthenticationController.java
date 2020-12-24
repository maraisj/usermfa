package za.co.allegra.medscheme.user.controller;

import com.google.zxing.WriterException;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.ObjectUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import za.co.allegra.medscheme.user.dto.Token;
import za.co.allegra.medscheme.user.service.AuthenticationService;

import javax.validation.Valid;
import java.io.IOException;
import java.security.Principal;

@RestController
@RequestMapping("/authenticate")
@CrossOrigin
@Log4j2
public class JwtAuthenticationController {
    private AuthenticationService authenticationService;

    public JwtAuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping
    public ResponseEntity<Token> createAuthenticationToken(@RequestHeader(value = "Authorization", required = true) String authorization) {
        if (ObjectUtils.isNotEmpty(authorization) && authorization.contains("Basic ")) {
            String token = authenticationService.authenticateAndGetToken(authorization);
            return ResponseEntity.ok(new Token(token));
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    @PostMapping(value = "mfa")
    @PreAuthorize("hasAuthority('PRE_AUTHENTICATED_MFA_REQUIRED')")
    public ResponseEntity<Token> createAuthenticationTokenWithMFA(@RequestBody @Valid Mfa mfa, Principal principal) {
        return ResponseEntity.ok(new Token(authenticationService.validateMFAAndGetToken(principal, mfa)));
    }

    @GetMapping(value = "/barcode", produces = MediaType.IMAGE_PNG_VALUE)
    @PreAuthorize("hasAuthority('PRE_AUTHENTICATED_MFA_REQUIRED')")
    public @ResponseBody
    byte[] createBarcode(Principal principal) throws IOException, WriterException {
        return authenticationService.getBarCodeByteArray(principal);
    }
}