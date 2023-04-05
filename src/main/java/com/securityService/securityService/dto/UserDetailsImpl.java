package com.securityService.securityService.dto;
import com.securityService.securityService.Entity.RegisteredUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class UserDetailsImpl implements UserDetails {

    private String username;
    private String password;
    private boolean active;
    private List<GrantedAuthority> authorityList;

    public UserDetailsImpl(Optional<RegisteredUser> user){
        this.username=user.get().getUsername();
        this.password=user.get().getPassword();
        this.active=user.get().isActive();
        this.authorityList= Arrays.stream(user.get().getRoles().split(",")).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorityList;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.active;
    }
}
