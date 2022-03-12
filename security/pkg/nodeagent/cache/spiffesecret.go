package cache

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"istio.io/istio/pkg/security"
	"istio.io/pkg/log"
)

// SpiffeSecretManager is a source of SecretItems (X.509 SVIDs and trust bundles) maintained via the
// Workload API. Implements the
type SpiffeSecretManager struct {
	sync.RWMutex
	trustDomain       spiffeid.TrustDomain
	configTrustBundle []byte
	secretItem        *security.SecretItem
	notifyCallback    func(resourceName string)
	cancelWatcher     context.CancelFunc
	updatedCh         chan struct{}
}

// NewSpiffeSecretManager creates a new SpiffeSecretManager. It blocks until the initial update
// has been received from the Workload API.
func NewSpiffeSecretManager(opt *security.Options) (*SpiffeSecretManager, error) {
	td, err := spiffeid.TrustDomainFromString(opt.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("error trying to parse trust domain %q reason: %v", opt.TrustDomain, err)
	}

	sm := &SpiffeSecretManager{
		trustDomain: td,
	}

	ctx, cancel := context.WithCancel(context.Background())
	sm.cancelWatcher = cancel
	sm.updatedCh = make(chan struct{})

	go sm.watcherTask(ctx)

	err = sm.WaitUntilUpdated(ctx)
	if err != nil {
		return nil, fmt.Errorf("error initializing the SPIFFE secret manager")
	}

	return sm, nil
}

// WaitUntilUpdated waits until the secret manager is updated or the context is done,
// in which case ctx.Err() is returned.
func (w *SpiffeSecretManager) WaitUntilUpdated(ctx context.Context) error {
	select {
	case <-w.updatedCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Updated returns a channel that is sent on whenever the secret manager is updated.
func (w *SpiffeSecretManager) Updated() <-chan struct{} {
	return w.updatedCh
}

// GenerateSecret generates a SecretItem for the given resourceName (default or ROOTCA).
func (s *SpiffeSecretManager) GenerateSecret(resourceName string) (*security.SecretItem, error) {
	s.RLock()
	defer s.RUnlock()

	si := s.secretItem
	if si == nil {
		return nil, fmt.Errorf("secret was not in cache for resource: %v", resourceName)
	}

	if resourceName == security.RootCertReqResourceName {

		ns := &security.SecretItem{
			ResourceName: resourceName,
			RootCert:     si.RootCert,
			// adding all trust bundles
			TrustBundles: si.TrustBundles,
		}

		cacheLog.WithLabels("ttl", time.Until(si.ExpireTime)).Info("returned workload trust anchor from cache")
		return ns, nil
	}

	ns := &security.SecretItem{
		ResourceName:     resourceName,
		CertificateChain: si.CertificateChain,
		PrivateKey:       si.PrivateKey,
		ExpireTime:       si.ExpireTime,
		CreatedTime:      si.CreatedTime,
	}
	cacheLog.WithLabels("ttl", time.Until(si.ExpireTime)).Info("returned workload certificate from cache")
	return ns, nil
}

// UpdateConfigTrustBundle updates the configTrustBundle and calls the notify callback function.
func (s *SpiffeSecretManager) UpdateConfigTrustBundle(trustBundle []byte) error {
	log.WithLabels("UpdateConfigTrustBundle").Info(string(trustBundle))
	s.Lock()
	defer s.Unlock()

	if bytes.Equal(s.configTrustBundle, trustBundle) {
		return nil
	}
	s.configTrustBundle = trustBundle
	s.callUpdateCallback(security.RootCertReqResourceName)
	return nil
}

// Close closes the SPIFFE secret manager instance.
func (s *SpiffeSecretManager) Close() {
	if s.cancelWatcher != nil {
		log.Info("closing SPIFFE secret manager")
		s.cancelWatcher()
	}
}

// SetUpdateCallback configures the manager with a notify callback function.
func (s *SpiffeSecretManager) SetUpdateCallback(f func(resourceName string)) {
	s.Lock()
	defer s.Unlock()
	s.notifyCallback = f
}

// OnX509ContextUpdate is run every time a new update is pushed by the SPIFFE Workload API.
func (s *SpiffeSecretManager) OnX509ContextUpdate(c *workloadapi.X509Context) {
	log.Info("got new identities from the SPIFFE Workload API")
	if len(c.SVIDs) < 1 {
		log.Error("identities were not found on workload API response")
		return
	}
	if len(c.SVIDs[0].Certificates) < 1 {
		log.Error("leaf certificate was not found on workload API response")
		return
	}

	svid := c.DefaultSVID()
	workloadChain, workloadKey, err := svid.Marshal()
	if err != nil {
		log.Fatalf("unable to marshal X.509 SVID: %v", err)
		return
	}

	bundle, ok := c.Bundles.Get(s.trustDomain)
	if !ok {
		log.WithLabels("trust_domain", s.trustDomain).Fatal("unable to get trust bundle for trust domain")
		return
	}

	root, err := bundle.Marshal()
	if err != nil {
		log.Fatalf("unable to marshal trust bundle: %v", err)
		return
	}

	certChain := concatCerts([]string{string(workloadChain)})
	leaf := c.SVIDs[0].Certificates[0]

	item := &security.SecretItem{
		CertificateChain: certChain,
		PrivateKey:       workloadKey,
		RootCert:         root,
		TrustBundles:     c.Bundles,
		ResourceName:     security.WorkloadKeyCertResourceName,
		CreatedTime:      leaf.NotBefore,
		ExpireTime:       leaf.NotAfter,
	}

	s.Lock()
	defer s.Unlock()

	if s.secretItem == nil || !bytes.Equal(s.secretItem.RootCert, item.RootCert) {
		s.callUpdateCallback(security.RootCertReqResourceName)
	}
	if s.secretItem == nil || !bytes.Equal(s.secretItem.CertificateChain, item.CertificateChain) {
		s.callUpdateCallback(security.WorkloadKeyCertResourceName)
	}
	s.secretItem = item

	select {
	case s.updatedCh <- struct{}{}:
		log.Info("notify message sent on updateCh")
	default:
		log.Info("notify message dropped")
	}
}

// OnX509ContextWatchError is run when the client runs into an error.
func (s *SpiffeSecretManager) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Infof("error calling SPIFE Workload API: %v", err)
	}
}

func (s *SpiffeSecretManager) callUpdateCallback(resourceName string) {
	log.WithLabels("resource", resourceName).Info("fetched new identity from SPIFFE Workload API")
	if s.notifyCallback != nil {
		s.notifyCallback(resourceName)
	}
}

func (s *SpiffeSecretManager) watcherTask(ctx context.Context) {
	err := workloadapi.WatchX509Context(ctx, s)
	if err != nil && status.Code(err) != codes.Canceled {
		log.Fatalf("error watching SPIFFE workload API: %v", err)
	}
}
