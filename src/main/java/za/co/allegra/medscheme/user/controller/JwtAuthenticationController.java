package za.co.allegra.medscheme.user.controller;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.ObjectUtils;
import org.jboss.aerogear.security.otp.Totp;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import za.co.allegra.medscheme.user.dto.ApplicationUser;
import za.co.allegra.medscheme.user.dto.Token;
import za.co.allegra.medscheme.user.service.JwtUserDetailsService;
import za.co.allegra.medscheme.user.util.JwtTokenUtil;

import javax.validation.Valid;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
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

    @RequestMapping(value = "/authenticate/barcode", method = RequestMethod.GET, produces = MediaType.IMAGE_PNG_VALUE)
    @PreAuthorize("hasAuthority('PRE_AUTHENTICATED_MFA_REQUIRED')")
    public @ResponseBody
    byte[] createBarcode(Principal principal) throws IOException, WriterException {
        String mfaSecret = ((ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal()).getMfaSecret();
        String username = ((ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal()).getUsername();
//        String secretKey = "QDWSM3OYBPGTEVSPB5FKVDM3CSNCWHVK";
        String companyName = "Allegra";
        String barCodeUrl = getGoogleAuthenticatorBarCode(mfaSecret, username, companyName);
        System.out.println(barCodeUrl);
        byte[] qrCode = createQRCode(barCodeUrl, 200, 200);
        return qrCode;
    }

    private void authenticate(String username, String password) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (AuthenticationException e) {
            log.info("Exception with authentication: " + e.getLocalizedMessage());
            throw e;
        }
    }

    private String getGoogleAuthenticatorBarCode(String secretKey, String account, String issuer) {
        try {
            return "otpauth://totp/"
                    + URLEncoder.encode(issuer + ":" + account, "UTF-8").replace("+", "%20")
                    + "?secret=" + URLEncoder.encode(secretKey, "UTF-8").replace("+", "%20")
                    + "&issuer=" + URLEncoder.encode(issuer, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] createQRCode(String barCodeData, int height, int width)
            throws WriterException, IOException {
        BitMatrix matrix = new MultiFormatWriter().encode(barCodeData, BarcodeFormat.QR_CODE, width, height);
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            MatrixToImageWriter.writeToStream(matrix,"png",bos);
            return bos.toByteArray();
        }
//        try (FileOutputStream out = new FileOutputStream(filePath)) {
//
//            MatrixToImageWriter.writeToStream(matrix, "png", out);
//            out.
//        }

    }
}