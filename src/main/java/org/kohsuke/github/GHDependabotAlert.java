package org.kohsuke.github;

import com.fasterxml.jackson.annotation.JsonProperty;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.IOException;
import java.net.URL;
import java.time.Instant;
import java.util.Date;
import java.util.stream.Stream;

/**
 * A dependabot alert in the dependabot alerts API.
 *
 * @author Tobias Gaisser
 * @see <a href="https://docs.github.com/en/rest/dependabot/alerts">documentation</a>
 */
@SuppressFBWarnings(
        value = { "UWF_UNWRITTEN_PUBLIC_OR_PROTECTED_FIELD", "UWF_UNWRITTEN_FIELD", "NP_UNWRITTEN_FIELD",
                "UUF_UNUSED_FIELD" },
        justification = "JSON API")
public class GHDependabotAlert extends GHObject {
    private int number;
    private GHDependabotAlert.State state;
    private Dependency dependency;
    private GHRepository repository;
    private String url, html_url;
    private SecurityAdvisory securityAdvisory;

    private String dismissed_reason;
    // TODO: security_vulnerability

    public State getState() {
        return state;
    }

    public Severity getSeverity() {
        return securityAdvisory.severity;
    }

    public String getCveId() {
        return securityAdvisory.cve_id;
    }

    public String getPackageName() {
        return dependency.aPackage.name;
    }

    public String getPackageEcosystem() {
        return dependency.aPackage.ecosystem;
    }

    public Double getCvssScore() {
        return securityAdvisory.cvss.score;
    }

    public String[] getCweIds() {
        return Stream.of(securityAdvisory.cwes).map(cwe -> cwe.cwe_id).toArray(String[]::new);
    }

    public Date getPublishedAt() {
        return parseDate(securityAdvisory.published_at);
    }

    public Date getUpdatedAdvisoryAt() {
        return parseDate(securityAdvisory.updated_at);
    }

    public String getWithdrawnAt() {
        return securityAdvisory.withdrawn_at;
    }

    public Scope getScope() {
        return dependency.scope;
    }

    private Date parseDate(String s) {
        return Date.from(Instant.parse(s));
    }

    static class Dependency {
        @JsonProperty("package")
        Package aPackage;
        String manifest_path;
        Scope scope;
    }

    static class Package {
        String ecosystem;
        String name;
    }

    static class SecurityAdvisory {
        String ghsa_id;
        String cve_id;
        String summary;
        String description;
        Vulnerability[] vulnerabilities;
        Severity severity;
        Cvss cvss;
        Cwes[] cwes;
        // TODO: identifiers (key-value pairs)
        // TODO: references
        // TODO einige weitere
        String published_at;
        String updated_at;
        String withdrawn_at;
    }

    static class Vulnerability {
        @JsonProperty("package")
        Package aPackage;
        Severity severity;
        String vulnerable_version_range;
        // TODO first_patched_version
    }

    public static class Cvss {
        Double score;
        String vector_string;
    }

    public static class Cwes {
        String cwe_id;
        String name;
    }

    public static enum Scope {
        DEVELOPMENT, RUNTIME;

        private Scope() {

        }
    }

    public static enum State {
        DISMISSED, FIXED, OPEN;

        private State() {
        }
    }

    public static enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL;

        private Severity() {
        }
    }

    private GHDependabotAlert() {// no external construction allowed
    }

    static GHDependabotAlert[] getForRepository(GitHub root, String owner, String name) throws IOException {
        return root.createRequest()
                .withUrlPath("/repos/" + owner + '/' + name + "/dependabot/alerts")
                .fetch(GHDependabotAlert[].class);
    }

    /**
     * Gets the html url.
     *
     * @return the html url
     * @deprecated This object has no HTML URL.
     */
    @Override
    public URL getHtmlUrl() {
        return null;
    }

    /**
     * Gets repository.
     *
     * @return the repository
     */
    @SuppressFBWarnings(value = { "EI_EXPOSE_REP" }, justification = "Expected behavior")
    public GHRepository getRepository() {
        return repository;
    }
}
