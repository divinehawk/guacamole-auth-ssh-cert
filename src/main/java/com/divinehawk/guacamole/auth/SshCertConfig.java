package com.divinehawk.guacamole.auth;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;

import static com.divinehawk.guacamole.auth.SshCertProperties.*;

/**
 * Reads this extension's configuration from guacamole.properties once, and
 * exposes the fully-constructed CaKeyManager, SshCertProvisioner, and
 * PrincipalConfigLoader built from it.
 *
 * Held as a singleton by SshCertAuthenticationProvider so the CA key
 * is loaded and verified exactly once at startup, not on every login.
 */
public class SshCertConfig {

    private final CaKeyManager caKeyManager;
    private final SshCertProvisioner provisioner;
    private final PrincipalConfigLoader principalConfigLoader;

    public SshCertConfig() throws GuacamoleException {

        Environment environment = LocalEnvironment.getInstance();

        String caKeyPath = environment.getRequiredProperty(CA_KEY_PATH);
        int certTtlSeconds = environment.getProperty(CERT_TTL_SECONDS, 300);
        String principalsFile = environment.getProperty(PRINCIPALS_FILE, null);
        String KeyType = environment.getProperty(SSH_CERT_KEY_TYPE, null);

        this.caKeyManager = new CaKeyManager(caKeyPath);
        this.provisioner = new SshCertProvisioner(caKeyManager, certTtlSeconds, KeyType);
        this.principalConfigLoader = new PrincipalConfigLoader(principalsFile);
    }

    public SshCertProvisioner getProvisioner() {
        return provisioner;
    }

    public PrincipalConfigLoader getPrincipalConfigLoader() {
        return principalConfigLoader;
    }
}
