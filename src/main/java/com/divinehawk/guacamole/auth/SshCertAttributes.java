package com.divinehawk.guacamole.auth;

/**
 * Names of extension-contributed attributes used by this extension.
 * Centralized here so the schema declaration (getConnectionAttributes())
 * and the code that reads the value back (SshCertTokenInjectingUserContext)
 * can't drift out of sync.
 */
public class SshCertAttributes {

    private SshCertAttributes() {}

    /**
     * Connection attribute holding a comma-separated list of additional
     * SSH certificate principals to grant for this specific connection,
     * on top of the user's own identity and anything granted via the
     * principals mapping file.
     */
    public static final String CONNECTION_PRINCIPALS = "ssh-cert-principals";
}
