# Prosentriq Sensor SDK for Python

Send events to Prosentriq from anything you can run Python on, receive
directives back, and run the Prosentriq sensors: the host bridge, the
syslog/CEF/Suricata relay, and the AWS VPC Flow Logs and CloudTrail collector.

Events follow the open [Prosentriq event schema](schema/prosentriq-event.schema.json)
(OCSF-aligned). The control plane serves the same schema at
`GET /v2/public/schema`.

## Install

The SDK needs Python 3.9 or later. It is published on PyPI as
[`prosentriq-sdk`](https://pypi.org/project/prosentriq-sdk/). While the current
release is a pre-release, add `--pre`:

```bash
pip install --pre prosentriq-sdk
# with the AWS collector:
pip install --pre 'prosentriq-sdk[aws]'
```

## Use it as a library

Create an enrollment key in the console (Sensors → Create enrollment key), then:

```python
from prosentriq_sdk import Client, events

enrolled = Client.enroll("https://api.prosentriq.com", enrollment_key,
                         hostname="appliance-1", sensor_type="sdk", os="linux")
# Store enrolled["token"] (shown once) and pin enrolled["signing_key"]["public_key"].
client = Client("https://api.prosentriq.com", enrolled["token"])
client.send([events.auth("185.220.101.4", user="admin", success=False, host_id="appliance-1")])

for directive in client.heartbeat()["directives"]:
    ...  # apply it, then acknowledge it on the next heartbeat
```

`prosentriq_sdk.events` has builders for network, authentication, process,
file, DNS and cloud API activity, and for findings.

## Run a sensor

The package installs the `prosentriq-sensor` command:

```bash
# Enroll each sensor once. The key is read from a file ('-' for stdin) or
# PROSENTRIQ_ENROLL_KEY, so it never appears in the process list.
prosentriq-sensor enroll --api-base https://api.prosentriq.com --enroll-key-file key.txt \
    --type log_relay --out relay.json
prosentriq-sensor relay --config relay.json --listen 0.0.0.0:5514      # syslog, CEF, Suricata

prosentriq-sensor enroll --api-base https://api.prosentriq.com --enroll-key-file key.txt \
    --type cloud_collector --out cloud.json
prosentriq-sensor cloud --config cloud.json --kind cloudtrail --s3 my-bucket/AWSLogs --loop 300

prosentriq-sensor verify-feed --config relay.json   # check the signed immunity feed against the pinned key
```

`prosentriq-sensor <command> --help` lists every option.

## Documentation

The full guides are in [PROSENTRIQ/docs](https://github.com/PROSENTRIQ/docs):
[your own sensor](https://github.com/PROSENTRIQ/docs/blob/main/install/custom-sensor.md),
[sending events](https://github.com/PROSENTRIQ/docs/blob/main/api/events.md),
[log sources](https://github.com/PROSENTRIQ/docs/blob/main/install/log-sources.md) and
[AWS](https://github.com/PROSENTRIQ/docs/blob/main/install/aws.md).

## Licence

Apache License 2.0; see [LICENSE](LICENSE). The SDK is open source; the
Prosentriq control plane it talks to is a commercial product.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as
described in the [security policy](https://github.com/PROSENTRIQ/.github/blob/main/SECURITY.md).
