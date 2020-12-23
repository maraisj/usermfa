package za.co.allegra.medscheme.user.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import za.co.allegra.medscheme.user.domain.ApplicationUserEntity;
import za.co.allegra.medscheme.user.domain.ApplicationUserRepository;
import za.co.allegra.medscheme.user.dto.ApplicationUserMapper;

import java.util.Optional;

@Service
public class JwtUserDetailsService implements UserDetailsService {
    private ApplicationUserRepository applicationUserRepository;
    private ApplicationUserMapper applicationUserMapper;

    public JwtUserDetailsService(ApplicationUserRepository applicationUserRepository, ApplicationUserMapper applicationUserMapper) {
        this.applicationUserRepository = applicationUserRepository;
        this.applicationUserMapper = applicationUserMapper;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        Optional<ApplicationUserEntity> byUsername = applicationUserRepository.findByUsername(username);
        if (byUsername.isPresent()) {
            return applicationUserMapper.mapFromEntityToDto(byUsername.get());
        } else {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
    }
}