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

import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.user.api.XWikiUser;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.xwiki.test.junit5.mockito.ComponentTest;

/**
 * Validate {@link OIDCClientBearerTokenValidator}.
 *
 * @version $Id$
 * @since 2.20.4
 */
@ComponentTest
class OIDCClientBearerTokenValidatorTest
{
    @InjectMockComponents
    private OIDCClientBearerTokenValidator validator;

    @MockComponent
    private OIDCClientConfiguration configuration;

    @MockComponent
    private OIDCUserManager users;

    private XWikiContext context;

    @BeforeEach
    void setUp()
    {
        this.context = mock(XWikiContext.class);
    }

    @Test
    void authenticateReturnsNullWhenDisabled()
    {
        when(this.configuration.isClientBearerEnabled()).thenReturn(false);

        XWikiUser result = this.validator.authenticate("some.jwt.token", this.context);

        assertNull(result);
    }

    @Test
    void authenticateDoesNotCallUsersWhenDisabled()
    {
        when(this.configuration.isClientBearerEnabled()).thenReturn(false);

        this.validator.authenticate("some.jwt.token", this.context);

        verify(this.users, never()).resolveUserByIdentity("some.jwt.token", this.context);
    }

    @Test
    void authenticateReturnsNullForInvalidJWT()
    {
        when(this.configuration.isClientBearerEnabled()).thenReturn(true);

        XWikiUser result = this.validator.authenticate("not-a-jwt", this.context);

        assertNull(result);
    }

    @Test
    void authenticateReturnsNullForEmptyToken()
    {
        when(this.configuration.isClientBearerEnabled()).thenReturn(true);

        XWikiUser result = this.validator.authenticate("", this.context);

        assertNull(result);
    }

    @Test
    void authenticateRejectsHMACAlgorithm()
    {
        when(this.configuration.isClientBearerEnabled()).thenReturn(true);

        // JWT with alg: HS256 (HMAC, not RSA)
        String header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"iss\":\"test\",\"aud\":\"aud\",\"exp\":9999999999}".getBytes());
        String hmacJwt = header + "." + payload + ".fakesignature";

        XWikiUser result = this.validator.authenticate(hmacJwt, this.context);

        assertNull(result);
    }

    @Test
    void authenticateRejectsNoneAlgorithm()
    {
        when(this.configuration.isClientBearerEnabled()).thenReturn(true);

        // JWT with alg: none (unsigned)
        String header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"iss\":\"test\",\"aud\":\"aud\",\"exp\":9999999999}".getBytes());
        String noneJwt = header + "." + payload + ".";

        XWikiUser result = this.validator.authenticate(noneJwt, this.context);

        assertNull(result);
    }

    @Test
    void authenticateReturnsNullWhenNoProviderAndNoIssuer() throws Exception
    {
        when(this.configuration.isClientBearerEnabled()).thenReturn(true);
        when(this.configuration.getClientProvider()).thenReturn(null);
        when(this.configuration.getClientBearerIssuer()).thenReturn(null);

        // Structurally valid RS256 JWT
        String fakeJwt = buildFakeRSAJwt();

        XWikiUser result = this.validator.authenticate(fakeJwt, this.context);

        assertNull(result);
    }

    @Test
    void authenticateReturnsNullWhenNoProviderAndEmptyIssuer() throws Exception
    {
        when(this.configuration.isClientBearerEnabled()).thenReturn(true);
        when(this.configuration.getClientProvider()).thenReturn(null);
        when(this.configuration.getClientBearerIssuer()).thenReturn("");

        String fakeJwt = buildFakeRSAJwt();

        XWikiUser result = this.validator.authenticate(fakeJwt, this.context);

        assertNull(result);
    }

    /**
     * Build a structurally valid JWT with RS256 algorithm that won't pass signature verification.
     */
    private String buildFakeRSAJwt()
    {
        String header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"iss\":\"test\",\"aud\":\"aud\",\"exp\":9999999999}".getBytes());

        return header + "." + payload + ".fakesignature";
    }
}
