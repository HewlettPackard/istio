# Integrating SPIRE as a CA through Envoy's SDS API

Further details about this integration can be found [here](https://istio.io/latest/docs/ops/integrations/spire).

This sample deploys a setup of [SPIRE](https://github.com/spiffe/spire) (the SPIFFE Runtime Environment) as an example of [Envoy's SDS](https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret) API integration in Istio. For more information
on SPIFFE and SPIRE specs, refer to the [SPIFFE Overview](https://spiffe.io/docs/latest/spiffe-about/overview/).

Once SPIRE is deployed and integrated with Istio, we will use a modified version of the [sleep](/samples/sleep/README.md) service and validate that its [identity](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#spiffe-verifiable-identity-document-svid) did come from SPIRE. 

## Usage

1. Deploy SPIRE. For proper socket injection, this **must** be done prior to installing Istio in your cluster:

    ```bash
    $ kubectl apply -f spire-quickstart.yaml
    ```

2. Ensure that the deployment is completed until moving to the next step. 

    This can be verified by waiting on the `spire-agent` pod to become ready:

    ```bash
    $ kubectl wait pod --for=condition=ready -n spire -l app=spire-agent
    ```

3. Use the configuration profile provided to install Istio:

    ```
    $ istioctl install -f istio-config.yaml
    ```

4. Deploy the modified version of [sleep](/samples/sleep/README.md) that injects the custom istio-agent template.

    If you have [automatic sidecar injection](https://istio.io/docs/setup/additional-setup/sidecar-injection/#automatic-sidecar-injection) enabled:

    ```
    $ kubectl apply -f sleep.yaml
    ```

    Otherwise manually inject the sidecars before applying:

    ```bash
    $ kubectl apply -f <(istioctl kube-inject -f sleep.yaml)
    ```


5. Retrieve sleep's SVID through `istioctl proxy-config secret` command:

    ```bash
    $ export SLEEP_POD=$(kubectl get pod -l app=sleep -o jsonpath="{.items[0].metadata.name}")
    $ istioctl pc secret $SLEEP_POD -o json | jq -r '.dynamicActiveSecrets[0].secret.tlsCertificate.certificateChain.inlineBytes' | base64 --decode > chain.pem
    ```

5. Inspect the certificate and verify that SPIRE is the issuer:

    ```bash
    $ openssl x509 -in chain.pem -text | grep SPIRE
        Subject: C = US, O = SPIRE, CN = sleep-5d6df95bbf-kt2tt
    ```

## Tear down

1.  Delete all deployments and configurations for the agent, server, and namespace:
    
    ```bash
    $ kubectl delete namespace spire
    ```

1.  Delete the ClusterRole and ClusterRoleBinding:
    
    ```bash
    $ kubectl delete clusterrole spire-server-trust-role spire-agent-cluster-role
    $ kubectl delete clusterrolebinding spire-server-trust-role-binding spire-agent-cluster-role-binding
    ```