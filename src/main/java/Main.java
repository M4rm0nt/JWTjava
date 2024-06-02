import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Main {

    enum Roles {
        ADMIN, USER
    }

    record JWT(String token) {}
    static class User {
        Integer id;
        Roles role;
        String username;

        public User(Integer id, Roles role, String username) {
            this.id = id;
            this.role = role;
            this.username = username;
        }

        public Integer getId() {
            return id;
        }

        public void setId(Integer id) {
            this.id = id;
        }

        public Roles getRole() {
            return role;
        }

        public void setRole(Roles role) {
            this.role = role;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }
    }

    private static Integer nextId = 0;

    private static Integer getNextId() {
        return nextId++;
    }

    private static Map<String, Object> createClaims(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", user.getId());
        claims.put("role", user.getRole());
        claims.put("username", user.getUsername());
        return claims;
    }

    private static Key generateSigningKey() {
        return Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    private static Date calculateExpiration(long expirationMillis) {
        return new Date(System.currentTimeMillis() + expirationMillis);
    }

    private static String generateJwtToken(Map<String, Object> claims, Date expiration, Key signingKey) {
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(expiration)
                .signWith(signingKey)
                .compact();
    }

    private static Jws<Claims> parseJwtToken(String jwtToken, Key signingKey) throws Exception {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(jwtToken);
    }

    private static void printJwtToken(JWT jwt) {
        System.out.println("Generated JWT: " + jwt.token());
    }

    private static void printParsedClaims(Map<String, Object> parsedClaims) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        String claimsJson = objectMapper.writeValueAsString(parsedClaims);
        System.out.println("Parsed Claims: " + claimsJson);
    }

    public static void main(String[] args) {

        Key signingKey = generateSigningKey();

        Integer nextId = getNextId();

        User admin = new User(nextId, Roles.ADMIN, "Marmont");

        Map<String, Object> claims = createClaims(admin);

        Date expiration = calculateExpiration(3600000);

        String jwtToken = generateJwtToken(claims, expiration, signingKey);

        JWT jwt = new JWT(jwtToken);

        printJwtToken(jwt);

        try {
            Jws<Claims> parsedToken = parseJwtToken(jwtToken, signingKey);

            Map<String, Object> parsedClaims = parsedToken.getBody();

            printParsedClaims(parsedClaims);
        } catch (Exception e) {
            System.out.println("Error parsing JWT: " + e.getMessage());
        }
    }
}