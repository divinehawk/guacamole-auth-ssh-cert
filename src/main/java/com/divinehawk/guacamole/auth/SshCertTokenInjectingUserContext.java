package com.divinehawk.guacamole.auth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.form.TextField;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.TokenInjectingUserContext;
import org.apache.guacamole.net.auth.UserContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.divinehawk.guacamole.auth.SshCertProvisioner.SshCertCredential;

import static com.divinehawk.guacamole.auth.SshCertAttributes.CONNECTION_PRINCIPALS;

/**
 * Wraps an already-authenticated UserContext (produced by whatever
 * extension actually owns the stored connection definitions -- the
 * database extension, file-based user-mapping, etc.) so that every
 * connect() call against a Connection belonging to that context has a
 * freshly-generated, freshly-signed SSH certificate injected as connect()
 * tokens.
 *
 * A fresh keypair and certificate are generated on *every* connect() --
 * not once at login -- since certificates are deliberately short-lived and
 * a browser session can easily outlive a single certificate's TTL.
 *
 * For this to do anything, the underlying stored connection(s) must
 * reference ${SSH_CERT_PRIVATE_KEY} and ${SSH_CERT_CERTIFICATE} as the
 * values of their "private-key" and "public-key" SSH parameters -- see the
 * README for the exact connection parameter setup.
 */
public class SshCertTokenInjectingUserContext extends TokenInjectingUserContext {

    private static final Logger logger =
            LoggerFactory.getLogger(SshCertTokenInjectingUserContext.class);

    private final String identity;
    private final SshCertProvisioner provisioner;
    private final PrincipalConfigLoader principalConfigLoader;

    public SshCertTokenInjectingUserContext(UserContext context,
            AuthenticatedUser authenticatedUser, SshCertProvisioner provisioner,
            PrincipalConfigLoader principalConfigLoader) throws GuacamoleException {

        // No static tokens supplied at construction time -- everything is
        // generated dynamically per-connection in addTokens() below.
        super(context, Collections.emptyMap());

        this.identity = authenticatedUser.getIdentifier();
        this.provisioner = provisioner;
        this.principalConfigLoader = principalConfigLoader;
    }

    /**
     * Declares the "Additional Principals" field shown on the connection
     * edit page, in addition to (not instead of) whatever attributes the
     * wrapped UserContext already contributes -- overriding this without
     * merging would silently remove the JDBC extension's own attributes
     * (max-connections, weight, etc.) from every connection's edit page.
     *
     * Confirmed against the real guacamole-ext 1.6.0 javadoc:
     * UserContext.getConnectionAttributes() declares no checked exceptions
     * (unlike most other UserContext methods, which throw
     * GuacamoleException) -- an earlier version of this override declared
     * "throws GuacamoleException" and failed to compile as a result.
     *
     * The translation strings for the section header and field label live
     * in src/main/resources/translations/en.json under
     * "CONNECTION_ATTRIBUTES".
     */
    @Override
    public Collection<Form> getConnectionAttributes() {
        Collection<Form> forms = new ArrayList<>(super.getConnectionAttributes());
        forms.add(new Form("ssh-cert",
                Arrays.asList(new TextField(CONNECTION_PRINCIPALS))));
        return forms;
    }

    /**
     * Confirmed against the real guacamole-ext 1.6.0 javadoc:
     * TokenInjectingUserContext.addTokens(Connection, Map&lt;String,String&gt;)
     * is "protected void ... throws GuacamoleException", matching the
     * signature below exactly.
     */
    @Override
    protected void addTokens(Connection connection, Map<String, String> tokens)
            throws GuacamoleException {

        super.addTokens(connection, tokens);

        Set<String> principals = new LinkedHashSet<>(
                principalConfigLoader.resolvePrincipals(identity));

        Map<String, String> attributes = connection.getAttributes();
        if (attributes != null) {
            String connectionPrincipals = attributes.get(CONNECTION_PRINCIPALS);
            if (connectionPrincipals != null) {
                for (String principal : connectionPrincipals.split(",")) {
                    String trimmed = principal.trim();
                    if (!trimmed.isEmpty())
                        principals.add(trimmed);
                }
            }
        }

        logger.debug("Provisioning ephemeral SSH certificate for \"{}\" "
                + "(connection \"{}\") with principals {}.",
                identity, connection.getName(), principals);

        SshCertCredential credential =
                provisioner.provision(identity, new ArrayList<>(principals));

        tokens.put("SSH_CERT_USERNAME", identity);
        tokens.put("SSH_CERT_PRIVATE_KEY", credential.getPrivateKey());
        tokens.put("SSH_CERT_CERTIFICATE", credential.getCertificate());
    }
}
