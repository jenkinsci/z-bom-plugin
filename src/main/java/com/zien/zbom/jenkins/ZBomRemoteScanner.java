package com.zien.zbom.jenkins;

import hudson.ProxyConfiguration;
import hudson.util.Secret;
import hudson.remoting.VirtualChannel;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serial;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URI;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import jenkins.MasterToSlaveFileCallable;
import net.sf.json.JSONObject;

final class ZBomRemoteScanner extends MasterToSlaveFileCallable<ZBomScanResult> {
    @Serial
    private static final long serialVersionUID = 1L;

    private static final Set<String> EXCLUDES = Set.of(
            ".git", ".github", ".env", "node_modules", "dist", "build", "target");

    private final ZBomScanConfig config;

    ZBomRemoteScanner(ZBomScanConfig config) {
        this.config = config;
    }

    @Override
    public ZBomScanResult invoke(File workspaceFile, VirtualChannel channel) throws IOException, InterruptedException {
        Path workspace = workspaceFile.toPath().toAbsolutePath().normalize();
        Path source = resolvePath(workspace, config.source);
        Archive archive = prepareArchive(source);
        StringBuilder log = new StringBuilder();

        try {
            log.append("z-bom: archiving workspace source\n");
            JSONObject submit = submitScan(archive.path(), log);
            ZBomScanResult result = new ZBomScanResult();
            result.log = log.toString();

            if (booleanValue(submit, "skipped")) {
                log.append("z-bom: integration paused (skipped) - nothing to do\n");
                result.status = "SKIPPED";
                result.log = log.toString();
                return result;
            }

            String runId = requiredString(submit, "analysisRunId", "z-bom: no analysisRunId -> " + submit);
            log.append("z-bom: analysis run ").append(runId)
                    .append(" (idempotent=").append(booleanValue(submit, "idempotent")).append(")\n");

            String status = "UNKNOWN";
            if (config.waitForCompletion) {
                status = waitForRun(runId, log);
            }

            JSONObject scanResult = getJson(api("/api/analysis-runs/" + encodePath(runId) + "/result"), 60);
            JSONObject severity = objectValue(scanResult, "cveSeverity");

            result.analysisRunId = runId;
            result.status = status;
            result.critical = intValue(severity, "CRITICAL", 0);
            result.high = intValue(severity, "HIGH", 0);
            result.medium = intValue(severity, "MEDIUM", 0);
            result.low = intValue(severity, "LOW", 0);
            result.totalCve = intValue(scanResult, "totalCve", 0);
            result.sbomCount = intValue(scanResult, "sbomCount", 0);
            result.hbomCount = intValue(scanResult, "hbomCount", 0);
            result.projectId = valueOrEmpty(
                    stringValue(scanResult, "inspectionId", ""),
                    stringValue(scanResult, "projectId", ""));
            result.policyExitCode = policyExitCode(result);

            log.append(summaryMarkdown(result));
            if ("FAILED".equalsIgnoreCase(status)) {
                log.append("z-bom: analysis failed\n");
                result.policyExitCode = 1;
            } else if (result.policyExitCode != 0) {
                log.append("z-bom: fail-on=").append(config.failOn)
                        .append(" matched ").append(gateCount(result)).append(" CVE(s)\n");
            } else if (result.policyExitCode == 0) {
                log.append("z-bom: done\n");
            }
            result.log = log.toString();
            return result;
        } finally {
            if (archive.temporary()) {
                Files.deleteIfExists(archive.path());
            }
        }
    }

    private JSONObject submitScan(Path archive, StringBuilder log) throws IOException, InterruptedException {
        String boundary = "----z-bom-" + UUID.randomUUID().toString().replace("-", "");
        String idempotencyKey = config.repo + ":" + config.type + ":" + config.commit;
        String commitLabel = config.commit == null ? "" : config.commit.substring(0, Math.min(8, config.commit.length()));
        log.append("z-bom: submitting -> ").append(api("/api/ci/scan"))
                .append(" (repo=").append(config.repo)
                .append(" type=").append(config.type)
                .append(" commit=").append(commitLabel).append(")\n");

        HttpRequest request = requestBuilder(api("/api/ci/scan"), 120)
                .header("Idempotency-Key", idempotencyKey)
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(multipartPublisher(boundary, archive))
                .build();
        return parseJson("POST", request.uri().toString(), send(request));
    }

    private String waitForRun(String runId, StringBuilder log) throws IOException, InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(config.timeoutSeconds);
        String status = "UNKNOWN";
        while (true) {
            JSONObject run = getJson(api("/api/analysis-runs/" + encodePath(runId)), 60);
            status = stringValue(run, "status", "UNKNOWN");
            log.append("z-bom: status=").append(status).append('\n');
            if ("COMPLETED".equalsIgnoreCase(status) || "FAILED".equalsIgnoreCase(status)) {
                return status;
            }
            if (System.nanoTime() >= deadline) {
                log.append("z-bom: timeout after ").append(config.timeoutSeconds)
                        .append("s (status=").append(status).append(")\n");
                return status;
            }
            Thread.sleep(TimeUnit.SECONDS.toMillis(config.intervalSeconds));
        }
    }

    private int policyExitCode(ZBomScanResult result) throws IOException {
        int gate = gateCount(result);
        return !"none".equals(config.failOn) && gate > 0 ? 1 : 0;
    }

    private int gateCount(ZBomScanResult result) throws IOException {
        int gate = switch (config.failOn) {
            case "none" -> 0;
            case "critical" -> result.critical;
            case "high" -> result.critical + result.high;
            case "medium" -> result.critical + result.high + result.medium;
            case "low" -> result.critical + result.high + result.medium + result.low;
            default -> throw new IOException("Unknown fail-on policy: " + config.failOn);
        };
        return gate;
    }

    private String summaryMarkdown(ZBomScanResult result) {
        StringBuilder out = new StringBuilder();
        out.append("<!-- z-bom-action -->\n")
                .append("## Z-BOM SBOM scan result - `").append(result.status).append("`\n\n")
                .append("| item | value |\n")
                .append("|---|---|\n")
                .append("| type | ").append(config.type).append(" |\n")
                .append("| components | SBOM ").append(result.sbomCount)
                .append(" / HBOM ").append(result.hbomCount).append(" |\n")
                .append("| vulnerabilities | Critical ").append(result.critical)
                .append(" / High ").append(result.high)
                .append(" / Medium ").append(result.medium)
                .append(" / Low ").append(result.low)
                .append(" (total ").append(result.totalCve).append(") |\n");
        if (!isBlank(result.projectId)) {
            out.append("\nReport: ").append(stripTrailingSlash(config.webUrl))
                    .append("/inspection/").append(result.projectId).append("/summary\n");
        }
        return out.append('\n').toString();
    }

    private JSONObject getJson(String url, int timeoutSeconds) throws IOException, InterruptedException {
        HttpRequest request = requestBuilder(url, timeoutSeconds).GET().build();
        return parseJson("GET", url, send(request));
    }

    private JSONObject parseJson(String method, String url, String body) throws IOException {
        if (isBlank(body)) {
            return new JSONObject();
        }
        try {
            return JSONObject.fromObject(body);
        } catch (RuntimeException e) {
            throw new IOException(method + " " + url + " returned invalid JSON: " + abbreviate(body), e);
        }
    }

    private HttpRequest.Builder requestBuilder(String url, int timeoutSeconds) {
        return HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .header("Authorization", "Token " + config.token.getPlainText())
                .header("Accept", "application/json")
                .header("User-Agent", "Z-BOM-Jenkins/0.1");
    }

    private String send(HttpRequest request) throws IOException, InterruptedException {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .followRedirects(HttpClient.Redirect.NORMAL);
        applyProxy(builder);
        HttpClient client = builder.build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        int statusCode = response.statusCode();
        if (statusCode < 200 || statusCode >= 300) {
            throw new IOException(request.method() + " " + request.uri() + " failed: "
                    + statusCode + " " + abbreviate(response.body()));
        }
        return response.body();
    }

    private void applyProxy(HttpClient.Builder builder) {
        ProxyConfiguration proxy = config.proxy;
        if (proxy == null || proxy.getName() == null) {
            return;
        }
        builder.proxy(new ZBomProxySelector(proxy.getName(), proxy.getPort(), proxy.getNoProxyHost()));
        if (proxy.getUserName() != null) {
            Secret password = proxy.getSecretPassword();
            String plainPassword = password == null ? "" : password.getPlainText();
            builder.authenticator(new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    if (getRequestorType() == RequestorType.PROXY) {
                        return new PasswordAuthentication(proxy.getUserName(), plainPassword.toCharArray());
                    }
                    return null;
                }
            });
        }
    }

    private HttpRequest.BodyPublisher multipartPublisher(String boundary, Path archive) throws IOException {
        List<HttpRequest.BodyPublisher> publishers = new ArrayList<>();
        addField(publishers, boundary, "source", "JENKINS");
        addField(publishers, boundary, "repo", config.repo);
        addField(publishers, boundary, "type", config.type);
        addField(publishers, boundary, "commit", config.commit);
        addField(publishers, boundary, "branch", config.branch);
        addField(publishers, boundary, "trigger", config.trigger);
        Path fileName = archive.getFileName();
        publishers.add(bytes("--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\""
                + safeFilename(fileName == null ? "source.zip" : fileName.toString()) + "\"\r\n"
                + "Content-Type: application/zip\r\n\r\n"));
        publishers.add(HttpRequest.BodyPublishers.ofFile(archive));
        publishers.add(bytes("\r\n--" + boundary + "--\r\n"));
        return HttpRequest.BodyPublishers.concat(publishers.toArray(HttpRequest.BodyPublisher[]::new));
    }

    private static void addField(
            List<HttpRequest.BodyPublisher> publishers,
            String boundary,
            String name,
            String value) {
        publishers.add(bytes("--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n"
                + (value == null ? "" : value) + "\r\n"));
    }

    private static HttpRequest.BodyPublisher bytes(String value) {
        return HttpRequest.BodyPublishers.ofByteArray(value.getBytes(StandardCharsets.UTF_8));
    }

    private Archive prepareArchive(Path source) throws IOException {
        if (!Files.exists(source)) {
            throw new IOException("Source not found: " + source);
        }
        if (Files.isRegularFile(source)) {
            return new Archive(source, false);
        }
        if (!Files.isDirectory(source)) {
            throw new IOException("Source must be a file or directory: " + source);
        }

        Path zip = Files.createTempFile("z-bom-", ".zip");
        try (OutputStream output = Files.newOutputStream(zip);
             ZipOutputStream archive = new ZipOutputStream(output, StandardCharsets.UTF_8)) {
            Files.walkFileTree(source, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    Path directoryName = dir.getFileName();
                    if (!dir.equals(source)
                            && directoryName != null
                            && EXCLUDES.contains(directoryName.toString())) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    if (!attrs.isRegularFile() || isExcluded(source.relativize(file))) {
                        return FileVisitResult.CONTINUE;
                    }
                    ZipEntry entry = new ZipEntry(source.relativize(file).toString().replace(File.separatorChar, '/'));
                    entry.setTime(attrs.lastModifiedTime().toMillis());
                    archive.putNextEntry(entry);
                    Files.copy(file, archive);
                    archive.closeEntry();
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException | RuntimeException e) {
            Files.deleteIfExists(zip);
            throw e;
        }
        return new Archive(zip, true);
    }

    private static boolean isExcluded(Path relative) {
        for (Path part : relative) {
            if (EXCLUDES.contains(part.toString())) {
                return true;
            }
        }
        return false;
    }

    private String api(String path) {
        return stripTrailingSlash(config.serverUrl) + path;
    }

    private static String stripTrailingSlash(String value) {
        String result = value == null ? "" : value.trim();
        while (result.endsWith("/")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    private static Path resolvePath(Path workspace, String value) {
        Path path = Paths.get(value == null || value.isBlank() ? "." : value);
        return path.isAbsolute() ? path.normalize() : workspace.resolve(path).normalize();
    }

    private static JSONObject objectValue(JSONObject object, String key) {
        if (object == null || !object.containsKey(key) || object.get(key) == null) {
            return new JSONObject();
        }
        Object value = object.get(key);
        return value instanceof JSONObject json ? json : JSONObject.fromObject(value);
    }

    private static String stringValue(JSONObject object, String key, String fallback) {
        if (object == null || !object.containsKey(key)) {
            return fallback;
        }
        Object value = object.get(key);
        if (value == null || "null".equals(String.valueOf(value))) {
            return fallback;
        }
        String text = String.valueOf(value);
        return text.isBlank() ? fallback : text;
    }

    private static String requiredString(JSONObject object, String key, String message) throws IOException {
        String value = stringValue(object, key, "");
        if (value.isBlank()) {
            throw new IOException(message);
        }
        return value;
    }

    private static String valueOrEmpty(String first, String second) {
        return isBlank(first) ? second : first;
    }

    private static int intValue(JSONObject object, String key, int fallback) {
        if (object == null || !object.containsKey(key)) {
            return fallback;
        }
        Object value = object.get(key);
        if (value instanceof Number number) {
            return number.intValue();
        }
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static boolean booleanValue(JSONObject object, String key) {
        if (object == null || !object.containsKey(key)) {
            return false;
        }
        return Boolean.parseBoolean(String.valueOf(object.get(key)));
    }

    private static String encodePath(String value) {
        return value.replace("%", "%25").replace("/", "%2F").replace(" ", "%20");
    }

    private static String safeFilename(String value) {
        return value.replace("\\", "_").replace("/", "_").replace("\"", "_")
                .replace("\r", "_").replace("\n", "_");
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String abbreviate(String value) {
        if (value == null) {
            return "";
        }
        String compact = value.replace('\r', ' ').replace('\n', ' ');
        return compact.length() <= 2000 ? compact : compact.substring(0, 2000) + "...";
    }

    private static final class ZBomProxySelector extends ProxySelector {
        private final String name;
        private final int port;
        private final String noProxyHost;

        private ZBomProxySelector(String name, int port, String noProxyHost) {
            this.name = name;
            this.port = port;
            this.noProxyHost = noProxyHost;
        }

        @Override
        public List<Proxy> select(URI uri) {
            if (uri == null || uri.getHost() == null) {
                return List.of(Proxy.NO_PROXY);
            }
            String scheme = uri.getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return List.of(Proxy.NO_PROXY);
            }
            Proxy proxy = ProxyConfiguration.createProxy(uri.getHost().toLowerCase(Locale.ROOT), name, port, noProxyHost);
            return List.of(proxy);
        }

        @Override
        public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
            // Ignore.
        }
    }

    private record Archive(Path path, boolean temporary) {}
}
