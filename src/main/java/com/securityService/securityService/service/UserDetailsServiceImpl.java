package com.securityService.securityService.service;
import com.securityService.securityService.Entity.RegisteredUser;
import com.securityService.securityService.Repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {


    private final UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<RegisteredUser> user = userRepository.findByUsername(username);
        RegisteredUser registeredUser = user.orElseThrow(() -> new UsernameNotFoundException("Username Not Found!"));

        return new User(registeredUser.getUsername(),registeredUser.getPassword(),registeredUser.isActive(),true,true,true, getAuthorities(registeredUser.getRoles()));
    }

    private Collection<? extends GrantedAuthority> getAuthorities(String roles) {
        return Collections.singletonList(new SimpleGrantedAuthority(roles));
    }
}
