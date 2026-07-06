package com.zien.zbom.jenkins;

import hudson.util.Secret;
import java.io.Serial;
import java.io.Serializable;

final class ZBomScanConfig implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    String serverUrl;
    Secret token;
    String type;
    String source;
    String repo;
    String branch;
    String trigger;
    String commit;
    boolean waitForCompletion;
    int timeoutSeconds;
    int intervalSeconds;
    String failOn;
    String webUrl;
}
