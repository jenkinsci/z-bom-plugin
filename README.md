# Z-BOM Plugin

Uploads the current Jenkins workspace to Z-BOM through the CI scan API, waits for the analysis result, prints a summary in the build log, and optionally fails the build by CVE severity.

## Requirements

- Jenkins 2.479.3 or newer
- Java 17 or newer
- Jenkins credentials:
  - `Z_BOM_URL`: Secret text containing the Z-BOM API URL reachable from the Jenkins agent
  - `Z_BOM_TOKEN`: Secret text containing the Z-BOM CI token
  - `Z_BOM_WEB_URL`: optional Secret text containing the browser-facing Z-BOM URL for report links

The plugin creates the source ZIP, sends HTTP requests, parses JSON, and polls from inside the Jenkins agent JVM. The agent does not need `curl`, `jq`, Python, or zip.

## Pipeline Usage

```groovy
pipeline {
    agent any

    stages {
        stage('Z-BOM Scan') {
            steps {
                zbomScan(
                    serverUrl: 'Z_BOM_URL',
                    credentialsId: 'Z_BOM_TOKEN',
                    type: 'code',
                    failOn: 'none',
                    timeoutSeconds: 1800,
                    intervalSeconds: 10,
                    webUrl: 'Z_BOM_WEB_URL'
                )
            }
        }
    }
}
```

`serverUrl`, `credentialsId`, and `webUrl` may be either literal HTTP(S) URLs or Jenkins Secret text credential IDs. `credentialsId` is always used as the Z-BOM token credential ID.

## Minimal Usage

```groovy
zbomScan(
    serverUrl: 'Z_BOM_URL',
    credentialsId: 'Z_BOM_TOKEN'
)
```

Defaults:

- `type`: `code`
- `failOn`: `none`
- `timeoutSeconds`: `1800`
- `intervalSeconds`: `10`
- `webUrl`: same value as `serverUrl`

## Options

- `serverUrl`: Z-BOM API URL or Secret text credential ID. Required.
- `credentialsId`: Secret text credential ID for the Z-BOM token. Required.
- `type`: `code` or `firmware`.
- `failOn`: `none`, `critical`, `high`, `medium`, or `low`.
- `timeoutSeconds`: maximum wait time for analysis completion.
- `intervalSeconds`: polling interval.
- `webUrl`: optional report-link base URL or Secret text credential ID.

`failOn` behavior:

- `none`: never fail because of CVE counts
- `critical`: fail if Critical CVEs exist
- `high`: fail if Critical or High CVEs exist
- `medium`: fail if Critical, High, or Medium CVEs exist
- `low`: fail if Critical, High, Medium, or Low CVEs exist

## Network Notes

The API calls run on the Jenkins agent that owns the workspace. If Jenkins runs in Docker and Z-BOM runs on the host machine, `localhost` usually points to the Jenkins container, not the host. Use a URL reachable from the agent, for example:

```text
http://host.docker.internal:8000
```

## Build

```bash
mvn clean verify
```

The installable plugin is generated at:

```text
target/z-bom.hpi
```

For local development:

```bash
mvn hpi:run
```
