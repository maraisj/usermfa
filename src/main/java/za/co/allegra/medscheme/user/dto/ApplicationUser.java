package za.co.allegra.medscheme.user.dto;

import lombok.Data;
import org.jboss.aerogear.security.otp.api.Base32;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Data
public class ApplicationUser implements UserDetails {
    private long id;
    private String username;
    private String password;
    private Boolean enabled;
    private Boolean mfaEnabled;
    private TokenStatus tokenStatus;
    private String mfaSecret;
    private Set<SimpleGrantedAuthority> simpleGrantedAuthoritySet = new HashSet<>();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return simpleGrantedAuthoritySet;
    }

    public void addAuthority(String role) {
        simpleGrantedAuthoritySet.add(new SimpleGrantedAuthority(role));
    }

    @Override
    public boolean isAccountNonExpired() {
        return enabled;
    }

    @Override
    public boolean isAccountNonLocked() {
        return enabled;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return enabled;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
