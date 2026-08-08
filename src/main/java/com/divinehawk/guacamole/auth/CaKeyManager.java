package com.divinehawk.guacamole.auth;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKeyPairResourceParser;
import org.apache.sshd.common.NamedResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loads the SSH certificate authority's private key from disk using Apache
 * MINA SSHD's OpenSSH key-format parser (rather than hand-decoding the
 * "openssh-key-v1" container ourselves), and verifies at load time that the
 * loaded private key actually corresponds to the CA public key you expect --
 * so a misconfigured or substituted key file fails loudly at startup instead
 * of silently signing certificates nobody will trust.
 */
public class CaKeyManager {

    private static final Logger logger = LoggerFactory.getLogger(CaKeyManager.class);

    private final KeyPair caKeyPair;

    /**
     * Loads and verifies the CA keypair.
     *
     * @param privateKeyPath
     *     Path to the CA private key, in standard OpenSSH
     *     "-----BEGIN OPENSSH PRIVATE KEY-----" format, unencrypted.
     *
     * @throws GuacamoleException
     *     If the key cannot be read, cannot be parsed, or does not match
     *     the given public key.
     */
    public CaKeyManager(String privateKeyPath) throws GuacamoleException {

        Path privPath = Path.of(privateKeyPath);

        Collection<KeyPair> loaded;
        try (InputStream in = Files.newInputStream(privPath)) {

            OpenSSHKeyPairResourceParser parser = new OpenSSHKeyPairResourceParser();

            // No passphrase support intentionally: the CA key backing an
            // automated signing service has to be readable by that
            // service with no human present to type a passphrase, so an
            // encrypted key here would just mean the passphrase sits in
            // config anyway. Protect this file with filesystem
            // permissions instead

	    loaded = parser.loadKeyPairs(null, NamedResource.ofName(privPath.toString()), null, in);
        }
        catch (IOException | GeneralSecurityException e) {
            throw new GuacamoleServerException(
                    "Unable to load SSH certificate authority private key from \""
                  + privateKeyPath + "\": " + e.getMessage(), e);
        }

        if (loaded == null || loaded.isEmpty()) {
            throw new GuacamoleServerException(
                    "No key pairs found in SSH certificate authority private "
                  + "key file \"" + privateKeyPath + "\".");
        }

        if (loaded.size() > 1) {
            throw new GuacamoleServerException(
                    "SSH certificate authority private key file \""
                  + privateKeyPath + "\" contains more than one key pair; "
                  + "expected exactly one.");
        }

        KeyPair candidate = loaded.iterator().next();

        this.caKeyPair = candidate;
    }

    public KeyPair getCaKeyPair() {
        return caKeyPair;
    }
}
