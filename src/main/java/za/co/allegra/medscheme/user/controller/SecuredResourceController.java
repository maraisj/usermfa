package za.co.allegra.medscheme.user.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/secured")
public class SecuredResourceController {
    @GetMapping
    public ResponseEntity<String> secureResource() {
        return ResponseEntity.ok("Secured");
    }

    @GetMapping("/mfa")
    @PreAuthorize("hasAuthority('PRE_AUTHENTICATED_MFA_REQUIRED')")
    public ResponseEntity<String> secureResourceMFA(HttpServletRequest request, HttpServletResponse response) {
        return ResponseEntity.ok("Secured MFA");
    }

    @GetMapping("/nomfa")
    @PreAuthorize("hasAuthority('AUTHENTICATED')")
    public ResponseEntity<String> secureResourceMFAOrMFAPassed(HttpServletRequest request, HttpServletResponse response) {
        return ResponseEntity.ok("Secured NonMFA or MFA passed");
    }
}
