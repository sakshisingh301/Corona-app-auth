package com.securityService.securityService.service;


import com.securityService.securityService.Entity.RegisteredUser;
import com.securityService.securityService.Repository.UserRepository;
import com.securityService.securityService.config.JwtProvider;
import com.securityService.securityService.dto.AuthenticationResponse;
import com.securityService.securityService.dto.LoginRequestDto;
import com.securityService.securityService.dto.RegisterUserRequestDto;
import com.securityService.securityService.exception.CoronaAppGenException;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@AllArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    private final AuthenticationManager authenticationManager;

    private final UserDetailsServiceImpl userDetailsService;

    private final JwtProvider jwtProvider;

    @Transactional
    public void signup(RegisterUserRequestDto registerUserRequestDto){
        RegisteredUser registeredUser= new RegisteredUser();
        registeredUser.setUsername(registerUserRequestDto.getUsername());
        registeredUser.setPassword(passwordEncoder.encode(registerUserRequestDto.getPassword()));
        registeredUser.setRoles(registerUserRequestDto.getRoles());
        registeredUser.setActive(true);

        //Adding a new user to the DB
        userRepository.save(registeredUser);

    }

    public AuthenticationResponse login(LoginRequestDto loginRequestDto){
       Authentication authentication= authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(),loginRequestDto.getPassword()));
        try {
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        catch (BadCredentialsException e){
            throw new CoronaAppGenException("Credentials are not correct");
        }

        final UserDetails userDetails= userDetailsService.loadUserByUsername(loginRequestDto.getUsername());

        final String jwtToken= jwtProvider.generateToken(authentication);

        return new AuthenticationResponse(userDetails.getUsername(),jwtToken);
    }
}
