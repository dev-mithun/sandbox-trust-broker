package com.mit.sandbox.trust.broker.service;

import com.mit.sandbox.trust.broker.config.SandboxConfig;
import com.mit.sandbox.trust.broker.util.TokenConstants;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@RequiredArgsConstructor
@Service
public class SandboxKeyService {

    private final SandboxConfig sandboxConfig;

    @Getter
    private RSAKey rsaKey;

    @PostConstruct
    public void init() throws Exception {

        PrivateKey privateKey = loadPrivateKey(sandboxConfig.privateKeyPath());
        PublicKey publicKey = loadPublicKey(sandboxConfig.publicKeyPath());

        this.rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey)
                .privateKey(privateKey)
                .keyID(sandboxConfig.keyId())
                .build();
    }

    public RSAKey getPublicKey() {
        return rsaKey.toPublicJWK();
    }

    // -------- PRIVATE KEY --------

    private PrivateKey loadPrivateKey(String path) throws Exception {

        String key = Files.readString(Path.of(path));

        key = key
                .replace(TokenConstants.BEGIN_PRIVATE_KEY, "")
                .replace(TokenConstants.END_PRIVATE_KEY, "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(key);

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(decoded);

        KeyFactory kf = KeyFactory.getInstance(TokenConstants.ALGORITHM);

        return kf.generatePrivate(spec);
    }

    // -------- PUBLIC KEY --------

    private PublicKey loadPublicKey(String path) throws Exception {

        String key = Files.readString(Path.of(path));

        key = key
                .replace(TokenConstants.BEGIN_PUBLIC_KEY, "")
                .replace(TokenConstants.END_PUBLIC_KEY, "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(key);

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(decoded);

        KeyFactory kf = KeyFactory.getInstance(TokenConstants.ALGORITHM);

        return kf.generatePublic(spec);
    }
}