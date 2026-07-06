# Z-BOM SBOM Checker (Jenkins Plugin)

Submits your project's git-tracked source to a **self-hosted (on-premises) Z-BOM instance** for SBOM/CVE analysis and reports the results on the build. This plugin is a *client* for Z-BOM — it requires a Z-BOM deployment reachable from your Jenkins controller/agents and does **not** work standalone.

> ⚠️ **Status: under development.** Not yet published to the Jenkins Update Center.

## Planned usage

Pipeline step:

```groovy
zbomScan url: 'https://z-bom.internal.example',
         credentialsId: 'z-bom-ci-token',   // Secret text credential
         type: 'code',                      // code | firmware
         failOn: 'high'                     // critical | high | medium | low | none
```

The step archives the workspace's git-tracked source, submits it to `POST /api/ci/scan`, polls until the analysis completes, and publishes a summary (component counts, CVE severity breakdown, link to the full report on your Z-BOM console). `failOn` marks the build as failed when CVEs at or above the given severity are found.

## Prerequisites

- An on-premises Z-BOM deployment. For Z-BOM itself, contact [ZIEN](https://zi-en.io).
- A Z-BOM CI token (issued from Z-BOM's CI/CD integration settings), stored as a Jenkins *Secret text* credential.
- Network access from the Jenkins agent to the Z-BOM server.

## See also

- GitHub Actions equivalent: [Z-BOM SBOM Checker on the GitHub Marketplace](https://github.com/marketplace/actions/z-bom-sbom-checker)

## Contributing

Refer to the Jenkins community [contribution guidelines](https://github.com/jenkinsci/.github/blob/master/CONTRIBUTING.md).

## License

Licensed under MIT, see [LICENSE](LICENSE.md).
