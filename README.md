# JwtSpringSecurity2


JwtAuthorizationFilter Start : api 접근 시


로그인 시

1. JwtAuthenticationFilter Start 1번 메소드
2. PrincipalDetailsService (getAuthorities 실행)
3. Authentication authentication =
                authenticationManager.authenticate(authenticationToken);
4.PrincipalDetails principalDetailis = (PrincipalDetails) authentication.getPrincipal();

5. JwtAuthenticationFilter Start 2번 메소드 Success 실행
6. addHeader 를 통해서 데이터를 보내줌
