package za.co.allegra.medscheme.user.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import za.co.allegra.medscheme.user.service.TotpService;

@RestController
@RequestMapping("/randomSecret")
public class SecretGeneratorController {
    private TotpService totpService;

    public SecretGeneratorController(TotpService totpService) {
        this.totpService = totpService;
    }

    @GetMapping("/{length}")
    public ResponseEntity<String> getSecret(@PathVariable("length") int length) {
        return ResponseEntity.ok(totpService.generateSecret(length));
    }
}
