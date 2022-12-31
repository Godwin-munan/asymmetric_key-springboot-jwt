package com.munan.asymmetric_keyspringbootjwt.security.filters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collections;

import static jakarta.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

@Component
public class JwtAuthEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws ServletException, IOException, IOException {


        if(response.getStatus() == SC_BAD_REQUEST){
            response.setStatus(SC_BAD_REQUEST);
        }else{
            response.setStatus(SC_UNAUTHORIZED);
        }
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);



//        Exception exception1 = (Exception) request.getAttribute("exception");

        String message;

        if(authException.getCause() != null){
            message = authException.getCause().toString()+" "+ authException.getMessage();
        }else {
            message = authException.getMessage();
        }
        byte[] body = new ObjectMapper().writeValueAsBytes(Collections.singletonMap("error", message));
        response.getOutputStream().write(body);

    }
}
