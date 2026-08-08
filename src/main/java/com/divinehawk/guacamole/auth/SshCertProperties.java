package com.divinehawk.guacamole.auth;

import org.apache.guacamole.properties.StringGuacamoleProperty;
import org.apache.guacamole.properties.IntegerGuacamoleProperty;

/**
 * guacamole.properties keys used by this extension. Values are read via
 * Environment.getProperty()/getRequiredProperty() in SshCertConfig.
 */
public class SshCertProperties {

    private SshCertProperties() {}

    /**
     * Path to the CA private key (OpenSSH format, "BEGIN OPENSSH PRIVATE
     * KEY") used to sign ephemeral user certificates.
     */
    public static final StringGuacamoleProperty CA_KEY_PATH =
        new StringGuacamoleProperty() {
            @Override
            public String getName() { return "ssh-cert-ca-key"; }
        };

    /**
     * Certificate validity window in seconds. Each certificate's
     * valid-before time is computed as (now + this value) at the moment
     * it is issued. Defaults to 300 (5 minutes).
     */
    public static final IntegerGuacamoleProperty CERT_TTL_SECONDS =
        new IntegerGuacamoleProperty() {
            @Override
            public String getName() { return "ssh-cert-ttl-seconds"; }
        };

    /**
     * OpenSSH key type to use for ephemeral user keys -- "ssh-ed25519" or
     * "ssh-rsa". Defaults to "ssh-ed25519".
     */
    public static final StringGuacamoleProperty CERT_KEY_TYPE =
        new StringGuacamoleProperty() {
            @Override
            public String getName() { return "ssh-cert-key-type"; }
        };

    /**
     * Optional path to a file mapping OIDC identities to additional SSH
     * certificate principals. See PrincipalConfigLoader for file format.
     * If unset, each certificate's only principal is the user's own OIDC
     * identity.
     */
    public static final StringGuacamoleProperty PRINCIPALS_FILE =
        new StringGuacamoleProperty() {
            @Override
            public String getName() { return "ssh-cert-principals-file"; }
        };
}
