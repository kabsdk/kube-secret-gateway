// Package e2e holds tests that run the real kube-secret-gateway-agent binary,
// built from the agent module in this repository, against the real gateway
// handler, with only the Kubernetes API faked. The gateway and the agent are
// separate modules that share no code, so these tests are what shows that
// they agree on the HTTP contract.
package e2e
