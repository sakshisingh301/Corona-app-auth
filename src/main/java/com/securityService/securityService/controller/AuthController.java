package com.securityService.securityService.controller;

import com.securityService.securityService.dto.AuthenticationResponse;
import com.securityService.securityService.dto.LoginRequestDto;
import com.securityService.securityService.dto.RegisterUserRequestDto;
import com.securityService.securityService.service.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class  AuthController {

    private final AuthService authService;

    /**
     * This end point is used for registering new user
     *
     */
    @PostMapping("/signup")
    @ResponseBody
    public ResponseEntity<String> signup(@RequestBody RegisterUserRequestDto registerUserRequestDto){
        authService.signup(registerUserRequestDto);
        return new ResponseEntity<>("User Registration Successful",HttpStatus.OK);
    }

    /**
     * This end point is used for registering new user
     *
     */
    @PostMapping("/signin")
    public AuthenticationResponse login(@RequestBody LoginRequestDto loginRequestDto){
        return authService.login(loginRequestDto);

    }


}
