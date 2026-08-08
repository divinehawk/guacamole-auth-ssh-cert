package com.divinehawk.guacamole.auth;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loads a simple key/value mapping file associating OIDC-derived identities
 * with additional SSH certificate principals that should be granted to
 * that user, on top of their own identity.
 *
 * File format (one entry per line):
 *
 *   # comments start with '#' and are ignored
 *   default = readonly
 *   alice@example.com = root, admin
 *   bob@example.com = deploy
 *
 * The special key "default" applies to every authenticated user, in
 * addition to any user-specific entry that may also match. The file is
 * re-read automatically whenever its mtime changes, so principals can be
 * updated without restarting Guacamole.
 */
public class PrincipalConfigLoader {

    private static final Logger logger = LoggerFactory.getLogger(PrincipalConfigLoader.class);
    private static final String DEFAULT_KEY = "default";

    private final Path configPath;

    private volatile Map<String, List<String>> cachedMapping = Collections.emptyMap();
    private volatile long cachedMtime = -1;

    /**
     * @param configPath
     *     Path to the principals mapping file, or null to disable
     *     additional-principal lookup entirely (every certificate will
     *     then be scoped to exactly the user's own identity).
     */
    public PrincipalConfigLoader(String configPath) {
        this.configPath = configPath == null ? null : Path.of(configPath);
    }

    /**
     * Returns the full, de-duplicated set of SSH certificate principals
     * that should be granted to the given base identity: the identity
     * itself, plus any "default" entries, plus any entries specific to
     * this identity.
     */
    public List<String> resolvePrincipals(String baseIdentity) {

        Set<String> principals = new LinkedHashSet<>();
        principals.add(baseIdentity);

        Map<String, List<String>> mapping = getMapping();

        List<String> defaults = mapping.get(DEFAULT_KEY);
        if (defaults != null)
            principals.addAll(defaults);

        List<String> specific = mapping.get(baseIdentity);
        if (specific != null)
            principals.addAll(specific);

        return new ArrayList<>(principals);
    }

    private Map<String, List<String>> getMapping() {

        if (configPath == null)
            return Collections.emptyMap();

        try {
            long mtime = Files.getLastModifiedTime(configPath).toMillis();
            if (mtime == cachedMtime)
                return cachedMapping;

            Map<String, List<String>> parsed = parseFile(configPath);
            cachedMapping = parsed;
            cachedMtime = mtime;
            return parsed;
        }
        catch (IOException e) {
            logger.warn("Unable to read SSH certificate principals file \"{}\": {}. "
                    + "Falling back to each user's own identity as their only "
                    + "certificate principal.", configPath, e.getMessage());
            return cachedMapping;
        }
    }

    private Map<String, List<String>> parseFile(Path path) throws IOException {

        Map<String, List<String>> mapping = new ConcurrentHashMap<>();

        try (BufferedReader reader = Files.newBufferedReader(path)) {

            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {

                lineNumber++;
                String trimmed = line.trim();

                if (trimmed.isEmpty() || trimmed.startsWith("#"))
                    continue;

                int eq = trimmed.indexOf('=');
                if (eq < 0) {
                    logger.warn("Ignoring malformed line {} in SSH certificate "
                            + "principals file \"{}\": missing '='.", lineNumber, path);
                    continue;
                }

                String key = trimmed.substring(0, eq).trim();
                String value = trimmed.substring(eq + 1).trim();

                if (key.isEmpty())
                    continue;

                List<String> values = new ArrayList<>();
                for (String v : value.split(",")) {
                    String cleaned = v.trim();
                    if (!cleaned.isEmpty())
                        values.add(cleaned);
                }

                mapping.put(key, values);
            }
        }

        logger.debug("Loaded {} entries from SSH certificate principals file \"{}\".",
                mapping.size(), path);

        return mapping;
    }
}
