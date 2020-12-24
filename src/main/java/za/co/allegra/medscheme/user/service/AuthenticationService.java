package za.co.allegra.medscheme.user.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import lombok.extern.slf4j.Slf4j;
import org.jboss.aerogear.security.otp.Totp;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import za.co.allegra.medscheme.user.controller.Mfa;
import za.co.allegra.medscheme.user.dto.ApplicationUser;
import za.co.allegra.medscheme.user.util.JwtTokenUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.Base64;

@Service
@Slf4j
public class AuthenticationService {
    private AuthenticationManager authenticationManager;
    private JwtUserDetailsService userDetailsService;
    private JwtTokenUtil jwtTokenUtil;

    @Value("${mfa.companyName}")
    private String mfaCompanyName;
    
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
            MatrixToImageWriter.writeToStream(matrix, "png", bos);
            return bos.toByteArray();
        }
    }

    public byte[] getBarCodeByteArray(Principal principal) throws IOException, WriterException {
        String mfaSecret = ((ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal()).getMfaSecret();
        String username = ((ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal()).getUsername();
        return createQRCode(getGoogleAuthenticatorBarCode(mfaSecret, username, mfaCompanyName), 200, 200);
    }

    public String validateMFAAndGetToken(Principal principal, Mfa mfa) {
        Totp totp = new Totp(((ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal()).getMfaSecret());
        if (totp.verify(mfa.getMfaCode())) {
            return jwtTokenUtil.generateTokenMFAPassedOrNotRequiredToken(((ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal()));
        } else {
            throw new InsufficientAuthenticationException("MFA validation failed");
        }
    }
}
