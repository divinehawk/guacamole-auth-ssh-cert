package com.divinehawk.guacamole.auth;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;

/**
 * AuthenticationProvider which does not itself authenticate users, but
 * decorates the UserContext produced by whatever extension actually owns
 * connection definitions (database, file-based user-mapping, etc.) so that
 * every SSH connection it exposes gets a freshly-signed, short-lived SSH
 * certificate injected at connect time.
 *
 * This must be configured to load AFTER both the identity provider (e.g.
 * the OpenID Connect extension) and the connection-owning extension, since
 * decorate() only has something to wrap once both have already run. See
 * EXTENSION_PRIORITY in guacamole.properties / the docker environment.
 */
public class SshCertAuthenticationProvider extends AbstractAuthenticationProvider {

    /**
     * Loaded and verified exactly once, at first use -- not per login.
     * Guacamole extensions are typically instantiated once per guacamole
     * webapp lifetime, so a plain instance field (rather than reaching for
     * Guice) is sufficient here.
     */
    private volatile SshCertConfig config;

    @Override
    public String getIdentifier() {
        return "ssh-cert-auth";
    }

    @Override
    public AuthenticatedUser authenticateUser(Credentials credentials) {
        // This provider never performs primary authentication -- it only
        // decorates a user already authenticated by another provider.
        return null;
    }

    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser) {
        // No connections of our own to contribute; decorate() below is
        // where the actual work happens, once another extension has
        // already supplied a UserContext to wrap.
        return null;
    }

    @Override
    public UserContext decorate(UserContext context, AuthenticatedUser authenticatedUser,
            Credentials credentials) throws GuacamoleException {

        if (context == null)
            return null;

        SshCertConfig loadedConfig = getConfig();

        return new SshCertTokenInjectingUserContext(context, authenticatedUser,
                loadedConfig.getProvisioner(), loadedConfig.getPrincipalConfigLoader());
    }

    private SshCertConfig getConfig() throws GuacamoleException {
        SshCertConfig result = config;
        if (result == null) {
            synchronized (this) {
                result = config;
                if (result == null) {
                    result = new SshCertConfig();
                    config = result;
                }
            }
        }
        return result;
    }
}
