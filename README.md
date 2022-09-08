# Otterize SPIRE Integration Operator

![Otter Manning Helm](./otterhelm.png)


![build](https://img.shields.io/static/v1?label=build&message=passing&color=success)
![go report](https://img.shields.io/static/v1?label=go%20report&message=A%2B&color=success)
[![GoDoc reference example](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/nanomsg.org/go/mangos/v2)
![openssf](https://img.shields.io/static/v1?label=openssf%20best%20practices&message=passing&color=success)
![community](https://img.shields.io/badge/slack-Otterize_Slack-orange.svg?logo=slack)

[About](#about) | [Quickstart](https://docs.otterize.com/documentation/quick-tutorials/mtls) | [How does the SPIRE Integration Operator work?](#how-does-the-spire-integration-operator-work) | [Docs](https://docs.otterize.com/documentation/k8s-operators/credential-operator) | [Contributing](#contributing) | [Slack](#slack)

## About
The Otterize SPIRE Integration Operator automatically resolves pods to dev-friendly service names, registers them with a SPIRE server, and optionally provisions credentials as a Kubernetes Secrets.


## How does the SPIRE Integration Operator work?

### SPIRE entry registration
Once the operator [resolves the service name](#service-name-resolution-and-automatic-pod-labeling) for a pod, it labels the pod and registers an entry with the SPIRE server.

### Credential generation
After the operator has registered the pod, which happens automatically upon startup, the pod can use the SPIRE Workload API to generate credentials for the SVID `<servicename>.<namespace>`.

Additionally, the operator consults the label `otterize/tls-secret-name`. If that label exists, the operator creates a secret named after the value of the label with X.509 credentials within (a SPIRE SVID). This way, the pod can get autogenerated credentials without modifying its code.

For more information, see the docs.

### Service name resolution and automatic pod labeling
Service name resolution is performed one of two ways:
1. If an `otterize/service-name` label is present, that name is used.
2. If not, a recursive look up is performed for the Kubernetes resource owner for a Pod until the root is reached. For example, if you have a `Deployment` named `client`, which then creates and owns a `ReplicaSet`, which then creates and owns a `Pod`, then the service name for that pod is `client` - same as the name of the `Deployment`.

The value resulting from this process forms the value of the label `otterize/spire-integration-operator.service-name`.

## Contributing
1. Feel free to fork and open a pull request! Include tests and document your code in [Godoc style](https://go.dev/blog/godoc)
2. In your pull request, please refer to an existing issue or open a new one.
3. For instructions on developing for the operator, see the [README for that section](./src/README.md).

## Slack
[Join the Otterize Slack!](https://join.slack.com/t/otterizeworkspace/shared_invite/zt-1fnbnl1lf-ub6wler4QrW6ZzIn2U9x1A)