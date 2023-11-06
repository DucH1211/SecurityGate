package com.abohosale.security.SecurityGate.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

/**
 * Class used to create JWT for a Map collection of Claims
 *
 */
@Slf4j
@Component
public class JwtHelper {
    /**
     * Beans created from JwtConfig class
     */
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public JwtHelper(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public String createJwtForClaims(String subject, Map<String,String> claims){
        Calendar calendar = Calendar.getInstance(); // create a calendar with default time zone ane locale
        //Calendar is an abstract class for converting instant in time and calendar fields
        calendar.setTimeInMillis(Instant.now().toEpochMilli());
        calendar.add(Calendar.DATE, 1);

        JWTCreator.Builder jwtBuilder = JWT.create().withSubject(subject);

        //Add claims
        claims.forEach(jwtBuilder::withClaim);

        return jwtBuilder.withNotBefore(new Date())
                .withExpiresAt(calendar.getTime())
                .sign(Algorithm.RSA256(publicKey,privateKey)); //return a String of jwt signed with RSA key extracted before.
    }
}
