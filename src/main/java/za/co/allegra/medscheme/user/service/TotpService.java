package za.co.allegra.medscheme.user.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import org.jboss.aerogear.security.otp.Totp;
import org.jboss.aerogear.security.otp.api.Base32;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import za.co.allegra.medscheme.user.domain.Mfa;
import za.co.allegra.medscheme.user.dto.ApplicationUser;
import za.co.allegra.medscheme.user.util.JwtTokenUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Principal;
import java.security.SecureRandom;

@Service
public class TotpService {
    private JwtTokenUtil jwtTokenUtil;

    public TotpService(JwtTokenUtil jwtTokenUtil) {
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @Value("${mfa.companyName}")
    private String mfaCompanyName;

    public byte[] getQRCodeByteArray(Principal principal) throws IOException, WriterException {
        String mfaSecret = ((ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal()).getMfaSecret();
        String username = ((ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal()).getUsername();
        return createQRCode(getQRCode(mfaSecret, username, mfaCompanyName), 200, 200);
    }

    public String validateMFAAndGetToken(Principal principal, Mfa mfa) {
        Totp totp = new Totp(((ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal()).getMfaSecret());
        if (totp.verify(mfa.getMfaCode())) {
            return jwtTokenUtil.generateTokenMFAPassedOrNotRequiredToken(((ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal()));
        } else {
            throw new InsufficientAuthenticationException("MFA validation failed");
        }
    }

    public String generateSecret(int secretLength) {
        SecureRandom randomBytes = new SecureRandom();
        byte[] bytes = new byte[(secretLength * 5) / 8];
        randomBytes.nextBytes(bytes);
        return Base32.encode(bytes);
    }

    private String getQRCode(String secretKey, String account, String issuer) {
        return "otpauth://totp/"
                + getUrlEncodedString(issuer + ":" + account)
                + "?secret=" + getUrlEncodedString(secretKey)
                + "&issuer=" + getUrlEncodedString(issuer);
    }

    private String getUrlEncodedString(String stringToBeEncoded) {
        try {
            return URLEncoder.encode(stringToBeEncoded, "UTF-8").replace("+", "%20");
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
}
