package com.securityService.securityService.Repository;
import com.securityService.securityService.Entity.RegisteredUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<RegisteredUser, Integer> {
    Optional<RegisteredUser> findByUsername(String username);
}
