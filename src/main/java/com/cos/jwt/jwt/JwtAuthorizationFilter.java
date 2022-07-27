package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 반드시 거쳐가는 필터
// Spring Security가 filter를 가지고 있는데 그 필터 중에 BasicAuthenticationFilter 라는 것이 있다
// 권한이나 인증이 필요한 특정 주소를 요청했 을 때 위 필터를 무조건 타게 되어 있고
// 만약 권한이나 인증이 필요없다면 해당 클래스는 작동하지 않는다
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        System.out.println("======================================");
        System.out.println("JwtAuthorizationFilter Start");
        System.out.println("======================================");

        System.out.println("인증이나 권한이 필요한 주소가 요청됨");

        // Authorization 에다가 JWT Header를 넘긴다
        String jwtHeader = request.getHeader("Authorization");

        System.out.println("jwtHeader : " + jwtHeader);

        // header 가 없으면 종료함
        // startWith 는 뭘로 시작하는지를 체크함(Bearer 로 시작하는지 확인)
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request,response);
            return;
        }

        // JWT 토큰을 검증을 해서 정상적인 사용자인지 확인해준다
        // Bearer을 제외한 토큰을 저장함
        String jwtToken = request.getHeader("Authorization").replace("Bearer ","");

        String username = JWT.require(Algorithm.HMAC512("cos")).build()
                .verify(jwtToken).getClaim("username").asString();

        // 서명이 정상적으로 됬다
        if(username != null){


            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            // userEntity가 들어간 객체 , 비밀번호, 권한체크
            // Jwt 토큰 서명을 통해서 정상이면 해당 객체를 만들어준다
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request,response);
        }
    }
}
