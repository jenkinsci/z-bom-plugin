package com.zien.zbom.jenkins;

import java.io.Serial;
import java.io.Serializable;

final class ZBomScanResult implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    String projectId;
    String analysisRunId;
    String status;
    int critical;
    int high;
    int medium;
    int low;
    int totalCve;
    int sbomCount;
    int hbomCount;
    int policyExitCode;
    String log;
}
