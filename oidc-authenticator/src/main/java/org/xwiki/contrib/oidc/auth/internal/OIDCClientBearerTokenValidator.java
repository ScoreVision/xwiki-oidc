/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.oidc.auth.internal;

import java.net.URI;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.user.api.XWikiUser;

/**
 * Validates JWT bearer tokens issued by the external OIDC provider (the identity provider this client
 * authenticates against) presented in the {@code Authorization} header of REST API requests. This is the
 * client-side counterpart to the provider-side token authenticator, which validates XWiki-issued tokens.
 *
 * @version $Id$
 * @since 2.20.4
 */
@Component(roles = OIDCClientBearerTokenValidator.class)
@Singleton
public class OIDCClientBearerTokenValidator
{
    private static final long CLOCK_SKEW_SECONDS = 60;

    @Inject
    private OIDCClientConfiguration configuration;

    @Inject
    private OIDCUserManager users;

    @Inject
    private Logger logger;

    /**
     * Validate a bearer token and resolve to an XWiki user.
     *
     * @param rawToken the raw JWT string from the Authorization header
     * @param context the XWiki context
     * @return the authenticated XWikiUser, or null if validation fails
     */
    public XWikiUser authenticate(String rawToken, XWikiContext context)
    {
        if (!this.configuration.isClientBearerEnabled()) {
            return null;
        }

        try {
            return doAuthenticate(rawToken, context);
        } catch (Exception e) {
            this.logger.debug("Bearer token authentication failed: [{}]", e.getMessage());

            return null;
        }
    }

    private XWikiUser doAuthenticate(String rawToken, XWikiContext context) throws Exception
    {
        SignedJWT jwt = parseAndValidateAlgorithm(rawToken);
        if (jwt == null) {
            return null;
        }

        JWTClaimsSet claims = verifySignature(jwt);
        if (claims == null) {
            return null;
        }

        if (!validateClaims(claims)) {
            return null;
        }

        String userIdentity = extractUserIdentity(claims);
        if (userIdentity == null) {
            return null;
        }

        this.logger.debug("Bearer token: resolved identity [{}]", userIdentity);

        return this.users.resolveUserByIdentity(userIdentity, context);
    }

    private SignedJWT parseAndValidateAlgorithm(String rawToken)
    {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(rawToken);
        } catch (ParseException e) {
            this.logger.debug("Bearer token is not a valid JWT");

            return null;
        }

        JWSAlgorithm alg = jwt.getHeader().getAlgorithm();
        if (!JWSAlgorithm.Family.RSA.contains(alg)) {
            this.logger.warn("Bearer token uses unsupported algorithm: [{}]", alg);

            return null;
        }

        return jwt;
    }

    private JWTClaimsSet verifySignature(SignedJWT jwt) throws Exception
    {
        URI jwksURI = getJWKSURI();
        if (jwksURI == null) {
            return null;
        }

        JWKSource<SecurityContext> jwkSource =
            JWKSourceBuilder.create(jwksURI.toURL()).build();

        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(
            new JWSVerificationKeySelector<>(JWSAlgorithm.Family.RSA, jwkSource));

        try {
            return jwtProcessor.process(jwt, null);
        } catch (BadJOSEException | JOSEException e) {
            this.logger.debug("Bearer token signature validation failed: [{}]", e.getMessage());

            return null;
        }
    }

    private boolean validateClaims(JWTClaimsSet claims) throws Exception
    {
        Date now = new Date();

        // Check expiration
        Date exp = claims.getExpirationTime();
        if (exp == null || now.after(new Date(exp.getTime() + CLOCK_SKEW_SECONDS * 1000))) {
            this.logger.debug("Bearer token expired. exp=[{}]", exp);

            return false;
        }

        // Check not-before
        Date nbf = claims.getNotBeforeTime();
        if (nbf != null && now.before(new Date(nbf.getTime() - CLOCK_SKEW_SECONDS * 1000))) {
            this.logger.debug("Bearer token not yet valid. nbf=[{}]", nbf);

            return false;
        }

        return validateIssuerAndAudience(claims);
    }

    private boolean validateIssuerAndAudience(JWTClaimsSet claims) throws Exception
    {
        // Issuer (fail-closed)
        String expectedIssuer = this.configuration.getClientBearerIssuer();
        if (expectedIssuer == null || expectedIssuer.isEmpty()) {
            this.logger.error("Bearer token auth: issuer not configured (fail-closed)");

            return false;
        }
        if (!expectedIssuer.equals(claims.getIssuer())) {
            this.logger.debug("Bearer token issuer mismatch: expected [{}], got [{}]",
                expectedIssuer, claims.getIssuer());

            return false;
        }

        // Audience (fail-closed)
        ClientID clientID = this.configuration.getClientID();
        if (clientID == null) {
            this.logger.error("Bearer token auth: client ID not configured (fail-closed)");

            return false;
        }
        List<String> audiences = claims.getAudience();
        if (audiences == null || !audiences.contains(clientID.getValue())) {
            this.logger.debug("Bearer token audience mismatch: expected [{}], got {}",
                clientID, audiences);

            return false;
        }

        return true;
    }

    private String extractUserIdentity(JWTClaimsSet claims)
    {
        String userClaim = this.configuration.getClientBearerUserClaim();
        String identity = getClaimValue(claims, userClaim);

        if (identity == null) {
            identity = getClaimValue(claims, "email");
        }
        if (identity == null) {
            identity = getClaimValue(claims, "upn");
        }
        if (identity == null) {
            identity = getClaimValue(claims, "preferred_username");
        }

        if (identity == null) {
            this.logger.warn("Bearer token: no user identity in claims "
                + "(tried: [{}], email, upn, preferred_username)", userClaim);
        }

        return identity;
    }

    /**
     * Get the JWKS URI, trying the provider metadata first, then deriving from the bearer issuer.
     */
    private URI getJWKSURI()
    {
        // Try provider metadata (available if OIDC discovery has been done)
        try {
            Object clientProvider = this.configuration.getClientProvider();
            if (clientProvider != null) {
                URI providerJwks =
                    ((org.xwiki.contrib.oidc.auth.internal.session.ClientProviders.ClientProvider)
                        clientProvider).getMetadata().getJWKSetURI();
                if (providerJwks != null) {
                    return providerJwks;
                }
            }
        } catch (Exception e) {
            this.logger.debug("Bearer token auth: provider metadata not available, "
                + "deriving JWKS from issuer");
        }

        // Derive from bearer issuer
        String issuer = this.configuration.getClientBearerIssuer();
        if (issuer == null || issuer.isEmpty()) {
            this.logger.error("Bearer token auth: no issuer configured, cannot derive JWKS URI");

            return null;
        }

        // Standard OIDC discovery: fetch from {issuer}/.well-known/openid-configuration
        try {
            String discoveryUrl = issuer.replaceAll("/+$", "")
                + "/.well-known/openid-configuration";
            java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(10)).build();
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(discoveryUrl))
                .timeout(java.time.Duration.ofSeconds(10)).GET().build();
            java.net.http.HttpResponse<String> resp =
                client.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());

            if (resp.statusCode() == 200) {
                // Parse jwks_uri from the discovery document
                String body = resp.body();
                int idx = body.indexOf("\"jwks_uri\"");
                if (idx >= 0) {
                    int start = body.indexOf('"', idx + 10) + 1;
                    int end = body.indexOf('"', start);
                    String jwksUri = body.substring(start, end);
                    this.logger.debug("Bearer token auth: JWKS URI from discovery: [{}]", jwksUri);

                    return URI.create(jwksUri);
                }
            }
        } catch (Exception e) {
            this.logger.debug("Bearer token auth: OIDC discovery failed: [{}]", e.getMessage());
        }

        this.logger.error("Bearer token auth: could not determine JWKS URI");

        return null;
    }

    private String getClaimValue(JWTClaimsSet claims, String name)
    {
        try {
            String val = claims.getStringClaim(name);

            return (val != null && !val.isEmpty()) ? val : null;
        } catch (ParseException e) {
            return null;
        }
    }
}
