package com.abohosale.security.SecurityGate.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Configure beans required for JWT signing and validation
 * contain the signing key information, signin key in kept in keystore
 * Beans to load keystore, get RSA public, private key,
 * and JWT Decoder.
 */
@Slf4j //for logging
@Configuration
public class JwtConfig {
    @Value("${app.security.jwt.keystore-location}")
    private String keyStorePath;

    @Value("${app.security.jwt.keystore-password}")
    private String keyStorePassword;

    @Value("${app.security.jwt.key-alias}")
    private String keyAlias;

    @Value("${app.security.jwt.private-key-passphrase}")
    private String privateKeyPassphrase;

    @Bean //KeyStore bean, return a KeyStore Object with the resource read from keystore.jks
    public KeyStore keyStore(){
        try{
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType()); //keystore object creation
            InputStream resourceAsStream = Thread.currentThread().
                    getContextClassLoader().getResourceAsStream(keyStorePath); //method to return InputStream got from reading a resource
            keyStore.load(resourceAsStream,keyStorePassword.toCharArray());
            return keyStore;
        }catch(IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e){
            log.error("Unable to load keystore: {}", keyStorePath,e);
        }
        throw new IllegalArgumentException("Unable to load keystore");
    }

    @Bean
    public RSAPrivateKey jwtSigningKey(KeyStore keyStore){
        try{
            Key key = keyStore.getKey(keyAlias,privateKeyPassphrase.toCharArray());
            if(key instanceof RSAPrivateKey){
                return (RSAPrivateKey) key;
            }
        }catch(UnrecoverableKeyException|NoSuchAlgorithmException|KeyStoreException e){
            log.error("Unable to load private key from keystore: {}", keyStorePath,e);
        }
        throw new IllegalArgumentException("Unable to load private key");
    }
    @Bean
    public RSAPublicKey jwtValidationKey(KeyStore keyStore){
        try{
            Certificate certificate = keyStore.getCertificate(keyAlias);
            PublicKey publicKey = certificate.getPublicKey();
            if(publicKey instanceof RSAPublicKey){
                return (RSAPublicKey) publicKey;
            }
        }catch(KeyStoreException e){
            log.error("Unable to load private key from keystore: {}", keyStorePath, e);
        }
        throw new IllegalArgumentException("Unable to load public key");
    }

    /**
     * At runtime, this configuration class will load the keystore, jwt signing key, and jwt validation key
     * then it will return a JwtDecoder bean, which uses the public key loaded from the key store to validate JWTs
     * which will be used by JwtAuthenticationProvider bean to decode and validate the JWT
     * @param rsaPublicKey
     * @return
     */
    @Bean
    public JwtDecoder jwtDecoder(RSAPublicKey rsaPublicKey){
        return NimbusJwtDecoder.withPublicKey(rsaPublicKey).build();
    }
}
