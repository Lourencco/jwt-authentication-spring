package com.example.demo.security;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.demo.model.Users;
import com.example.demo.service.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

@Service
public class JWTService {
	
	@Autowired
	UserService userService;
	long expirationTime = 3600000; // 1 hora
	
	private String secretKey;

	public JWTService() {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
			SecretKey sk= keyGen.generateKey();
			secretKey=Base64.getEncoder().encodeToString(sk.getEncoded());
			
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
	}
	
	public Cookie createTokenCookie(String token) {
	    Cookie cookie = new Cookie("token", token);
	    cookie.setHttpOnly(true); 
	    cookie.setSecure(true); 
	    cookie.setPath("/"); 
	    cookie.setMaxAge((int) expirationTime / 1000); 
	    return cookie;
	}


	public String generateToken(String idUsuario) {
		Users usuario = userService.getUserDetails(idUsuario);
		Map<String, Object> claims= new HashMap<>();
		claims.put("email", usuario.getEmail()); 
        claims.put("nome", usuario.getNome()); 
        claims.put("enabled", usuario.getNome()); 
        claims.put("username", usuario.getUsername());
        claims.put("idUsuario",usuario.getIdUsuario());
        claims.put("role",usuario.getRole());
		return Jwts.builder()
				.claims()
				.add(claims)
				.subject(idUsuario)
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + expirationTime))
				.and()
				.signWith(getKey())
				.compact();
	}

	private SecretKey getKey() {
		byte[] keyBytes=Decoders.BASE64.decode(secretKey);
		
		return Keys.hmacShaKeyFor(keyBytes);
	}
	
	
	public boolean validateToken(String token, String idUsuario) {
		final String userName=extractUsername(token);
		
		return (userName.equals(idUsuario) && !isTokenExpired(token));
	}
	private boolean isTokenExpired(String token) {
		
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		
		return extractClaim(token, Claims::getExpiration);
	}

	public String extractUsername(String token) {	
		
		return extractClaim(token,Claims::getSubject);	
	
	
	}
	private <T> T extractClaim(String token, Function<Claims, T> claimResolver){
		
		final Claims claims= extractAllClaims(token);
		return claimResolver.apply(claims);
	}
	
	private Claims extractAllClaims(String token) {
		return Jwts.parser()
				.verifyWith(getKey())
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}
	public String extractToken(HttpServletRequest request) {
	    String bearerToken = request.getHeader("Authorization");
	    if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
	        return bearerToken.substring(7);
	    }
	    return null;
	}

}
