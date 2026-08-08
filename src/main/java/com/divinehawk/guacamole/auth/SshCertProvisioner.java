package com.divinehawk.guacamole.auth;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

// VERIFY: confirm this class/method exists as-is in eddsa 0.3.0 on the
// classpath. Used because SSHD's own OpenSSHEd25519PrivateKeyEntryDecoder
// hands back net.i2p.crypto.eddsa.EdDSAPrivateKey instances (confirmed by
// the earlier ClassCastException), and java.security.Signature.getInstance(
// "Ed25519") is a *different*, JDK-native provider that will not accept an
// i2p-typed key. Signing the CA certificate has to go through the same
// i2p-backed implementation the keys actually are.
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;

/**
 * Generates ephemeral RSA or ed25519 keypairs and signs them into
 * short-lived SSH user certificates, entirely in-process -- no external
 * processes, no key material touching disk at any point.
 *
 * Key generation and OpenSSH-format private key serialization are handled
 * by Apache MINA SSHD (KeyUtils.generateKeyPair / OpenSSHKeyPairResourceWriter)
 * rather than hand-rolled binary encoding. Only the SSH *certificate* wire
 * format itself (which has no equivalent high-level writer readily
 * available) is assembled by hand below, field-by-field, against OpenSSH's
 * PROTOCOL.certkeys.
 *
 * Both the ephemeral user key type and the CA key type are handled
 * generically: the ephemeral key type is passed in per call, and the CA
 * key type is detected at runtime from the loaded CA keypair so that
 * signing uses the correct algorithm/digest for whichever CA key is
 * actually configured.
 */
public class SshCertProvisioner {

    private static final int CERT_TYPE_USER = 1;

    private final CaKeyManager caKeyManager;
    private final int certTtlSeconds;
    private final String KeyType;

    /**
     * @param KeyType
     *     The OpenSSH type name to use for every ephemeral user key this
     *     provisioner generates -- e.g. {@link KeyPairProvider#SSH_RSA} or
     *     {@link KeyPairProvider#SSH_ED25519}. Fixed per-provisioner
     *     instance; construct a second provisioner if you need to offer
     *     both types.
     */
    public SshCertProvisioner(CaKeyManager caKeyManager, int certTtlSeconds,
            String KeyType) {
        this.caKeyManager = caKeyManager;
        this.certTtlSeconds = certTtlSeconds;
        this.KeyType = validateKeyType(KeyType);
    }

    private static String validateKeyType(String keyType) {
        if (keyType == null)
            return KeyPairProvider.SSH_ED25519;

        if (KeyPairProvider.SSH_ED25519.equals(keyType) || KeyPairProvider.SSH_RSA.equals(keyType))
            return keyType;

        throw new IllegalArgumentException(
            "Unsupported ephemeral SSH key type: \"" + keyType + "\" (expected \""
           + KeyPairProvider.SSH_ED25519 + "\" or \"" + KeyPairProvider.SSH_RSA + "\").");
    }

    /**
     * Generates a fresh keypair (of this provisioner's configured type) and
     * signs it as an SSH user certificate valid for the given principals.
     *
     * @param keyId
     *     A log-friendly identifier embedded in the certificate ("-I"
     *     equivalent). Has no bearing on authorization; the principals
     *     list below is what a target server actually checks.
     *
     * @param principals
     *     The SSH principals this certificate should be valid for.
     *
     * @return
     *     The generated private key (OpenSSH PEM text) and signed
     *     certificate (single-line "type base64 comment" text), both held
     *     only in memory.
     */
    public SshCertCredential provision(String keyId, List<String> principals)
            throws GuacamoleException {

        String keyType = KeyType;

        if (principals == null || principals.isEmpty()) {
            throw new GuacamoleServerException(
                    "Refusing to sign an SSH certificate with no principals.");
        }

        KeyPair keyPair = generateKeyPair(keyType);
        String privateKeyPem = writePrivateKeyPem(keyPair, keyId);
        String certificate = signCertificate(keyType, keyPair, keyId, principals);

        return new SshCertCredential(privateKeyPem, certificate);
    }

    private KeyPair generateKeyPair(String keyType) throws GuacamoleException {
        try {
            return KeyUtils.generateKeyPair(keyType, defaultKeySize(keyType));
        }
        catch (GeneralSecurityException e) {
            throw new GuacamoleServerException(
                    "Failed to generate ephemeral " + keyType + " keypair: "
                  + e.getMessage(), e);
        }
    }

    private static int defaultKeySize(String keyType) {
        if (KeyPairProvider.SSH_RSA.equals(keyType))
            return 3072;
        if (KeyPairProvider.SSH_ED25519.equals(keyType))
            return 256; // ignored by the ed25519 decoder, but required as a param
        throw new IllegalArgumentException("Unsupported ephemeral key type: " + keyType);
    }

    private static String certTypeFor(String keyType) {
        if (KeyPairProvider.SSH_RSA.equals(keyType))
            return "ssh-rsa-cert-v01@openssh.com";
        if (KeyPairProvider.SSH_ED25519.equals(keyType))
            return "ssh-ed25519-cert-v01@openssh.com";
        throw new IllegalArgumentException("Unsupported ephemeral key type: " + keyType);
    }

    private String writePrivateKeyPem(KeyPair keyPair, String comment)
            throws GuacamoleException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            new OpenSSHKeyPairResourceWriter()
                    .writePrivateKey(keyPair, comment, null, out);
            return out.toString(StandardCharsets.UTF_8);
        }
        catch (Exception e) {
            throw new GuacamoleServerException(
                    "Failed to serialize ephemeral private key: " + e.getMessage(), e);
        }
    }

    /**
     * Writes the certificate's "pk" field(s), whose layout depends on the
     * ephemeral key's type per PROTOCOL.certkeys:
     *
     *   ed25519:  string pk        (raw 32-byte public key, no envelope)
     *   rsa:      string e; string n   (public exponent, modulus -- each
     *                                   a standard SSH mpint)
     */
    private static void putCertPublicKeyFields(ByteArrayBuffer tbs, String keyType,
            PublicKey publicKey) {

        if (KeyPairProvider.SSH_ED25519.equals(keyType)) {
            tbs.putRawPublicKeyBytes(publicKey);
            return;
        }

        if (KeyPairProvider.SSH_RSA.equals(keyType)) {
            RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
            // VERIFY: putMPInt(BigInteger) is SSHD's standard mpint writer
            // on Buffer/ByteArrayBuffer -- double check the exact overload
            // name against sshd-common 2.13.2 if this doesn't compile.
            tbs.putMPInt(rsaKey.getPublicExponent());
            tbs.putMPInt(rsaKey.getModulus());
            return;
        }

        throw new IllegalArgumentException("Unsupported ephemeral key type: " + keyType);
    }

    /**
     * Builds and signs an OpenSSH user certificate for the given ephemeral
     * keypair. Everything up to and including "signature key" is signed
     * as-is (no extra length prefix around the whole thing); the signature
     * is then appended as its own length-prefixed field.
     */
    private String signCertificate(String keyType, KeyPair keyPair, String keyId,
            List<String> principals) throws GuacamoleException {

        try {
            ByteArrayBuffer tbs = new ByteArrayBuffer();

            tbs.putString(certTypeFor(keyType));

            byte[] nonce = new byte[32];
            new SecureRandom().nextBytes(nonce);
            tbs.putBytes(nonce);

            putCertPublicKeyFields(tbs, keyType, keyPair.getPublic());

            long serial = Instant.now().toEpochMilli();
            tbs.putLong(serial);
            tbs.putInt(CERT_TYPE_USER);

            tbs.putString(keyId);

            ByteArrayBuffer principalsBuf = new ByteArrayBuffer();
            for (String principal : principals)
                principalsBuf.putString(principal);
            tbs.putBytes(principalsBuf.getCompactData());

            long now = Instant.now().getEpochSecond();
            long validAfter = now - 60;
            long validBefore = now + certTtlSeconds;
            tbs.putLong(validAfter);
            tbs.putLong(validBefore);

            // Critical options: none.
            tbs.putBytes(new byte[0]);

            // Extensions: the standard permissive set. Adjust here if you
            // want to restrict port/agent/X11 forwarding by policy rather
            // than relying solely on sshd_config on the target.
            ByteArrayBuffer extensionsBuf = new ByteArrayBuffer();
            for (String extension : new String[] {
                    "permit-X11-forwarding",
                    "permit-agent-forwarding",
                    "permit-port-forwarding",
                    "permit-pty",
                    "permit-user-rc" }) {
                extensionsBuf.putString(extension);
                extensionsBuf.putString("");
            }
            tbs.putBytes(extensionsBuf.getCompactData());

            // Reserved: empty.
            tbs.putBytes(new byte[0]);

            // Signature key: the CA's full public key blob (type + data),
            // itself wrapped as a length-prefixed field.
            ByteArrayBuffer caKeyBuf = new ByteArrayBuffer();
            caKeyBuf.putPublicKey(caKeyManager.getCaKeyPair().getPublic());
            tbs.putRawBytes(caKeyBuf.getCompactData());

            byte[] tbsData = tbs.getCompactData();
            byte[] rawSignature = signWithCaKey(tbsData);
            String caSigFormat = caSignatureFormat();

            ByteArrayBuffer sigBuf = new ByteArrayBuffer();
            sigBuf.putString(caSigFormat);
            sigBuf.putBytes(rawSignature);

            ByteArrayBuffer finalCert = new ByteArrayBuffer();
            // Concatenate the already-self-delimited tbs data directly --
            // no extra length prefix around it, unlike a putBuffer() call
            // would add.
            finalCert.putRawBytes(tbsData);
            finalCert.putBytes(sigBuf.getCompactData());

            String b64 = Base64.getEncoder().encodeToString(finalCert.getCompactData());
            return certTypeFor(keyType) + " " + b64 + " " + keyId;
        }
        catch (Exception e) {
            throw new GuacamoleServerException(
                    "Failed to sign ephemeral SSH certificate: " + e.getMessage(), e);
        }
    }

    /**
     * The "signature format" string embedded in the certificate's
     * signature blob -- this describes the CA's signing algorithm, NOT the
     * ephemeral user key's type. For an RSA CA this is one of the
     * rsa-sha2-* names (plain "ssh-rsa" / SHA-1 signatures are rejected by
     * modern OpenSSH); for an Ed25519 CA it's "ssh-ed25519".
     */
    private String caSignatureFormat() {
        PublicKey caPublicKey = caKeyManager.getCaKeyPair().getPublic();
        String algorithm = caPublicKey.getAlgorithm();

        if ("RSA".equalsIgnoreCase(algorithm))
            return "rsa-sha2-512";
        if (caPublicKey instanceof net.i2p.crypto.eddsa.EdDSAPublicKey
                || "EdDSA".equalsIgnoreCase(algorithm))
            return "ssh-ed25519";

        throw new IllegalStateException("Unsupported CA key algorithm: " + algorithm);
    }

    /**
     * Signs {@code tbsData} with the CA's private key, dispatching on the
     * CA key's actual type so RSA and Ed25519 CAs each go through a signer
     * implementation compatible with how that key was loaded.
     */
    private byte[] signWithCaKey(byte[] tbsData) throws GeneralSecurityException {
        PrivateKey caPrivateKey = caKeyManager.getCaKeyPair().getPrivate();

        if (caPrivateKey instanceof EdDSAPrivateKey) {
            // VERIFY: confirm EdDSAEngine's no-arg constructor + initSign/
            // update/sign here actually produces a valid "pure" Ed25519
            // signature (no prehashing) as OpenSSH certs require -- test
            // against a real `ssh-keygen -L` / target sshd before relying
            // on this in production.
            Signature signer = new EdDSAEngine();
            signer.initSign(caPrivateKey);
            signer.update(tbsData);
            return signer.sign();
        }

        if ("RSA".equalsIgnoreCase(caPrivateKey.getAlgorithm())) {
            Signature signer = Signature.getInstance("SHA512withRSA");
            signer.initSign(caPrivateKey);
            signer.update(tbsData);
            return signer.sign();
        }

        throw new IllegalStateException(
                "Unsupported CA private key type: " + caPrivateKey.getClass());
    }

    /**
     * A generated ephemeral private key and its corresponding signed SSH
     * certificate, held only in memory.
     */
    public static final class SshCertCredential {

        private final String privateKey;
        private final String certificate;

        SshCertCredential(String privateKey, String certificate) {
            this.privateKey = privateKey;
            this.certificate = certificate;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public String getCertificate() {
            return certificate;
        }
    }
}

