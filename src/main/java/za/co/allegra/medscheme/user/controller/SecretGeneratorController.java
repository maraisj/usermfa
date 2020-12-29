package za.co.allegra.medscheme.user.controller;

import org.jboss.aerogear.security.otp.api.Base32;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;

@RestController
@RequestMapping("/randomSecret")
public class SecretGeneratorController {
    @GetMapping("/{length}")
    public ResponseEntity<String> getSecret(@PathVariable("length") int length) {
        SecureRandom randomBytes = new SecureRandom();
        byte[] bytes = new byte[(length * 5) / 8];
        randomBytes.nextBytes(bytes);
        return ResponseEntity.ok(Base32.encode(bytes));
    }
}
