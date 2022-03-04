# Integrating SPIRE through Envoy SDS

There are currently multiple forms of integrating third-party Certificate Authorities (CA) whitin Istio. This example deploys a setup of [SPIRE](https://github.com/spiffe/spire) (the SPIFFE Runtime Environment) as an Exernal CA, through [Envoy's SDS API integration](https://github.com/alexandrealvino/istio.io/blob/6eff1cd45dfce244978cafc10a88f7620c0438fc/content/en/docs/ops/integrations/spire/index.md).

To assist this deployment, two additional components will be shipped together with SPIRE, the [CSI Driver](https://github.com/spiffe/spiffe-csi) and the [Kubernetes Workload Registrar](https://github.com/spiffe/spire/tree/main/support/k8s/k8s-workload-registrar).

The desired behaviour will get triggered during istio-agent bootstrap, in case a socket file under `/var/run/secrets/workload-spiffe-uds/socket` is detected. This tells istio-agent **not** to start its own SDS server, but to use the one provided via socket.


## Usage

1. Deploy Spire:

    ```bash
    kubectl apply -f spire.yaml
    ```

2. Wait until the deployment is completed. This can be verified by waiting on the `spire-agent` pod to become ready:

    ```bash
    export SPIRE_POD=$(kubectl get pod -n spire -l app=spire-agent -o jsonpath="{.items[0].metadata.name}")
    kubectl wait --for=condition=ready pod -n spire $SPIRE_POD
    ```

3. Apply the configuration profile provided to install istio:

    ```
    istioctl install -f profile.yaml
    ```

4. Deploy [Sleep](/samples/sleep/README.md), or any other service of your preference. Here, Sleep will only be used to validate that its identity was issued by SPIRE. 

5. Retrieve the certificate data issued for sleep service:

    ```bash
    export SLEEP_POD=$(kubectl get pod -l app=sleep -o jsonpath="{.items[0].metadata.name}")
    istioctl pc secret $SLEEP_POD -o json | jq -r '.dynamicActiveSecrets[0].secret.tlsCertificate.certificateChain.inlineBytes' | base64 --decode > chain.pem
    ```

5. Inspect the certificate and verify that SPIRE is the issuer:

    ```bash
    openssl x509 -in chain.pem -text | grep SPIRE
    ```