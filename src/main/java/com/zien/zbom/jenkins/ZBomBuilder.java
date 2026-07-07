package com.zien.zbom.jenkins;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

public class ZBomBuilder extends Builder implements SimpleBuildStep {
    private final String serverUrl;
    private final String credentialsId;

    private String type = "code";
    private String failOn = "none";
    private int timeoutSeconds = 1800;
    private int intervalSeconds = 10;
    private String webUrl = "";

    @DataBoundConstructor
    public ZBomBuilder(String serverUrl, String credentialsId) {
        this.serverUrl = serverUrl == null ? "" : serverUrl.trim();
        this.credentialsId = credentialsId == null ? "" : credentialsId.trim();
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    public String getType() {
        return type;
    }

    @DataBoundSetter
    public void setType(String type) {
        this.type = defaultString(type, "code");
    }

    public String getFailOn() {
        return failOn;
    }

    @DataBoundSetter
    public void setFailOn(String failOn) {
        this.failOn = defaultString(failOn, "none");
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    @DataBoundSetter
    public void setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }

    public int getIntervalSeconds() {
        return intervalSeconds;
    }

    @DataBoundSetter
    public void setIntervalSeconds(int intervalSeconds) {
        this.intervalSeconds = intervalSeconds;
    }

    public String getWebUrl() {
        return webUrl;
    }

    @DataBoundSetter
    public void setWebUrl(String webUrl) {
        this.webUrl = defaultString(webUrl, "");
    }

    @Override
    public void perform(
            Run<?, ?> run,
            FilePath workspace,
            EnvVars env,
            Launcher launcher,
            TaskListener listener) throws InterruptedException, IOException {
        validateBaseSettings();

        String expandedCredentialsId = env.expand(credentialsId);
        StringCredentials credentials = CredentialsProvider.findCredentialById(
                expandedCredentialsId, StringCredentials.class, run);
        if (credentials == null) {
            throw new AbortException("Z-BOM Secret text credential not found: " + expandedCredentialsId);
        }

        ZBomScanConfig config = new ZBomScanConfig();
        config.serverUrl = env.expand(serverUrl).trim();
        config.token = credentials.getSecret();
        config.type = env.expand(type).toLowerCase(Locale.ROOT);
        config.source = ".";
        config.repo = valueOrEnv(env.get("JOB_NAME"), env.get("GIT_URL"), "unknown");
        config.branch = valueOrEnv(env.get("BRANCH_NAME"), env.get("GIT_BRANCH"), "");
        config.trigger = "JENKINS";
        config.commit = valueOrEnv(env.get("GIT_COMMIT"), env.get("GITHUB_SHA"), "");
        config.waitForCompletion = true;
        config.timeoutSeconds = timeoutSeconds;
        config.intervalSeconds = intervalSeconds;
        config.failOn = env.expand(failOn).toLowerCase(Locale.ROOT);
        config.webUrl = valueOrEnv(env.expand(webUrl), config.serverUrl, "").trim();
        validateExpandedSettings(config);

        listener.getLogger().printf(
                "[Z-BOM] repo=%s type=%s server=%s%n",
                config.repo, config.type, config.serverUrl);

        ZBomScanResult result = workspace.act(new ZBomRemoteScanner(config));
        if (result.log != null && !result.log.isBlank()) {
            listener.getLogger().print(result.log);
        }

        if (result.policyExitCode != 0) {
            throw new AbortException("Z-BOM policy failed: failOn=" + failOn
                    + ", critical=" + result.critical
                    + ", high=" + result.high
                    + ", medium=" + result.medium
                    + ", low=" + result.low);
        }
    }

    private void validateBaseSettings() throws AbortException {
        if (serverUrl.isBlank()) {
            throw new AbortException("serverUrl is required");
        }
        if (credentialsId.isBlank()) {
            throw new AbortException("credentialsId is required");
        }
        if (timeoutSeconds <= 0) {
            throw new AbortException("timeoutSeconds must be greater than zero");
        }
        if (intervalSeconds <= 0) {
            throw new AbortException("intervalSeconds must be greater than zero");
        }
    }

    private static void validateExpandedSettings(ZBomScanConfig config) throws AbortException {
        if (!List.of("code", "firmware").contains(config.type)) {
            throw new AbortException("type must be code or firmware");
        }
        if (!List.of("none", "critical", "high", "medium", "low").contains(config.failOn)) {
            throw new AbortException("failOn must be none, critical, high, medium, or low");
        }
        if (!isHttpUrl(config.serverUrl)) {
            throw new AbortException("serverUrl must be an absolute HTTP or HTTPS URL");
        }
        if (!config.webUrl.isBlank() && !isHttpUrl(config.webUrl)) {
            throw new AbortException("webUrl must be an absolute HTTP or HTTPS URL");
        }
    }

    private static boolean isHttpUrl(String value) {
        try {
            URI uri = new URI(value);
            return ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
                    && uri.getHost() != null;
        } catch (URISyntaxException e) {
            return false;
        }
    }

    private static String valueOrEnv(String first, String second, String fallback) {
        if (first != null && !first.isBlank()) {
            return first;
        }
        if (second != null && !second.isBlank()) {
            return second;
        }
        return fallback;
    }

    private static String defaultString(String value, String fallback) {
        return value == null ? fallback : value.trim();
    }

    @Extension
    @Symbol("zbomScan")
    public static class DescriptorImpl extends BuildStepDescriptor<Builder> {
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Run Z-BOM scan";
        }

        @RequirePOST
        public ListBoxModel doFillCredentialsIdItems(
                @AncestorInPath Item context,
                @QueryParameter String credentialsId) {
            StandardListBoxModel model = new StandardListBoxModel();
            model.includeEmptyValue();
            if (context == null || !context.hasPermission(Item.CONFIGURE)) {
                model.includeCurrentValue(credentialsId);
                return model;
            }
            model.include(context, StringCredentials.class);
            model.includeCurrentValue(credentialsId);
            return model;
        }

        public ListBoxModel doFillTypeItems(@QueryParameter String type) {
            ListBoxModel model = new ListBoxModel();
            model.add("Source code", "code");
            model.add("Firmware", "firmware");
            return model;
        }

        public ListBoxModel doFillFailOnItems(@QueryParameter String failOn) {
            ListBoxModel model = new ListBoxModel();
            model.add("Do not fail the build", "none");
            model.add("Fail on critical CVEs", "critical");
            model.add("Fail on high or above CVEs", "high");
            model.add("Fail on medium or above CVEs", "medium");
            model.add("Fail on low or above CVEs", "low");
            return model;
        }

        @RequirePOST
        public FormValidation doCheckServerUrl(@AncestorInPath Item context, @QueryParameter String value) {
            if (context == null || !context.hasPermission(Item.CONFIGURE)) {
                return FormValidation.ok();
            }
            if (value == null || value.isBlank()) {
                return FormValidation.error("Z-BOM server URL is required");
            }
            return isHttpUrl(value.trim()) ? FormValidation.ok() : FormValidation.error("Must be an HTTP or HTTPS URL");
        }
    }
}
