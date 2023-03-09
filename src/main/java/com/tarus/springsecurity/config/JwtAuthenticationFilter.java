package com.tarus.springsecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//Should be active everytime a request is made
@Component
@RequiredArgsConstructor //creates constructor using any final field
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private  final JwtService jwtService;

    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
         @NonNull   HttpServletResponse response,
         @NonNull   FilterChain filterChain //contains next filter within the chain
    ) throws ServletException, IOException {
final String authHeader  = request.getHeader("Authorization");
final String jwt;
final String userEmail;
if(authHeader == null || !authHeader.startsWith("Bearer ")) {
    filterChain.doFilter(request,response); //next
    return;
}
jwt = authHeader.substring(7);

//extract useremail
        userEmail = jwtService.extractUsername(jwt);
/**@desc check is user is not null or the user is not authenticated*/
        if(userEmail!=null && SecurityContextHolder.getContext().getAuthentication() ==null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail); //get userDetails from database
            if(jwtService.isTokenValid(jwt,userDetails)){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
filterChain.doFilter(request,response);
    }
}
