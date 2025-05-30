package org.copilot.user.authentication.aop;

import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class UserAuthorizeAspect {

    @Before("@annotation(userAuthorize)")
    public void checkAuthorization(UserAuthorize userAuthorize) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AuthorizationException("Unauthorized access", HttpStatus.UNAUTHORIZED);
        }

        String role = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst().orElse("");

        if (!userAuthorize.value().equals(role)) {
            throw new AuthorizationException("Forbidden access", HttpStatus.FORBIDDEN);
        }
    }
}