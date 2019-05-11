package com.businesssystemssecurity.proj.security.conf;

import com.businesssystemssecurity.proj.exception.BadTokenException;
import com.businesssystemssecurity.proj.exception.EntityNotFoundException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class TokenUtils {

    @Value("${jwt.token.secret}")
    private String secret;

    @Value("${jwt.token.expiration}")
    private Long expiration;

    public Claims getClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            throw new BadTokenException();
        }
        return claims;
    }

    public boolean isTokenExpired(String token) {
        final Date expirationDate = this.getExpirationDateFromToken(token);
        return expirationDate.before(new Date(System.currentTimeMillis()));
    }

    public String getEmailFromToken(String token) {
        Claims claims = this.getClaimsFromToken(token);
        return claims.getSubject();
    }

    public Date getExpirationDateFromToken(String token) {
        final Claims claims = this.getClaimsFromToken(token);
        return claims.getExpiration();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String email = getEmailFromToken(token);
        return email.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public String generateToken(UserDetails userDetails) {
        Date currentDate = new Date(System.currentTimeMillis());
        Date expirationDate = new Date(System.currentTimeMillis() + expiration*1000);

        if (userDetails == null) {
            throw new EntityNotFoundException(UserDetails.class, "Object", "null");
        }

        if (userDetails.getUsername() == null) {
            throw new EntityNotFoundException(UserDetails.class, "email", "");
        }

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(currentDate)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }


}
