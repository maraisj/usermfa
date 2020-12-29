package za.co.allegra.medscheme.user.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import za.co.allegra.medscheme.user.dto.TokenStatus;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenUtil implements Serializable {
    private static final long serialVersionUID = -2550185165626007488L;
    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.tokenValidityMFAPassedOrNotRequired}")
    private long jwtTokenValidityMFAPassedOrNotRequired;
    @Value("${jwt.tokenValidityMFANotPassedYet}")
    private long jwtTokenValidityMFANotPassedYet;

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }


    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }


    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);

        return expiration.before(new Date());
    }

    public String generateTokenMFAPassedOrNotRequiredToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return generateTokenMFAPassedOrNotRequiredToken(claims, userDetails.getUsername());
    }

    private String generateTokenMFAPassedOrNotRequiredToken(Map<String, Object> claims, String subject) {
        claims.put("status", TokenStatus.AUTHENTICATED);
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtTokenValidityMFAPassedOrNotRequired * 1000))
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    public String generateTokenMFANotPassed(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return generateTokenMFANotPassed(claims, userDetails.getUsername());
    }

    private String generateTokenMFANotPassed(Map<String, Object> claims, String subject) {
        claims.put("status", TokenStatus.PRE_AUTHENTICATED_MFA_REQUIRED);
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtTokenValidityMFANotPassedYet * 1000))
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

}