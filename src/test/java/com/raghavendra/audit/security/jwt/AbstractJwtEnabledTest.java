package com.raghavendra.audit.security.jwt;

import com.raghavendra.audit.support.AbstractPostgresIntegrationTest;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/**
 * Base for JWT-enabled integration tests. It:
 * <ul>
 *   <li>generates local RSA keys and mints REAL signed tokens ({@link JwtTestSupport});</li>
 *   <li>serves the corresponding JWK set from a tiny standalone HTTP server on an ephemeral port —
 *       so the application's real {@code NimbusJwtDecoder} fetches real keys and performs real
 *       signature validation (never a mocked decoder, never {@code jwt()} post-processors);</li>
 *   <li>points {@code audit.security.jwt.*} at that JWK set and enables JWT with an issuer,
 *       audience, and RS256/ES256 allow-list.</li>
 * </ul>
 *
 * <p>Uses MockMvc against the app; the JWKS server is out-of-process from the Spring context, so no
 * real identity provider is contacted.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AbstractPostgresIntegrationTest.WithPostgres
public abstract class AbstractJwtEnabledTest {

    protected static final JwtTestSupport JWT = new JwtTestSupport();
    private static final HttpServer JWKS_SERVER;
    private static final String JWK_SET_URI;

    // Start the JWKS server at class load — BEFORE @DynamicPropertySource suppliers are evaluated
    // (which happens during context creation, ahead of @BeforeAll). This guarantees the jwk-set-uri
    // is known and reachable when the JwtDecoder is built.
    static {
        try {
            JWKS_SERVER = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            JWKS_SERVER.createContext("/jwks", exchange -> {
                byte[] body = JWT.publicJwkSetJson().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(body);
                }
            });
            JWKS_SERVER.start();
            JWK_SET_URI = "http://127.0.0.1:" + JWKS_SERVER.getAddress().getPort() + "/jwks";
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @AfterAll
    static void stopJwksServer() {
        if (JWKS_SERVER != null) {
            JWKS_SERVER.stop(0);
        }
    }

    @DynamicPropertySource
    static void jwtProperties(DynamicPropertyRegistry registry) {
        registry.add("audit.security.jwt.enabled", () -> "true");
        registry.add("audit.security.jwt.issuer-uri", () -> JwtTestSupport.ISSUER);
        registry.add("audit.security.jwt.jwk-set-uri", () -> JWK_SET_URI);
        registry.add("audit.security.jwt.audiences", () -> JwtTestSupport.AUDIENCE);
        registry.add("audit.security.jwt.allowed-algorithms", () -> "RS256,ES256");
    }

    protected static String bearer(String token) {
        return "Bearer " + token;
    }
}
