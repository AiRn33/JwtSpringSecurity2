package com.cos.jwt.auth;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login 이 올 때 동작
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {


        User userEntity = userRepository.findByUsername(username);

        System.out.println("======================================");
        System.out.println("PrinciplaDetailsService Start");
        System.out.println("======================================");

        System.out.println("PrincipalDetailsService의 loadUserByUsername()");
        System.out.println("userEntity" + userEntity);
        System.out.println("password Encode" + userEntity.getPassword());

        return new PrincipalDetails(userEntity);
    }
}
