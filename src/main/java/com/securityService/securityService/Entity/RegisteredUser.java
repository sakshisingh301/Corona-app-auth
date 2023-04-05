package com.securityService.securityService.Entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name="UserDetails")
public class RegisteredUser {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name= "Identifier")
    private int id;

    @Column(name = "Username")
    private String username;

    @Column(name = "Password")
    private String password;

    @Column(name = "IsActive")
    private boolean active;

    @Column(name="Roles")
    private String roles;


}
