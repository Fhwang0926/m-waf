package manager

import (
	"context"
	"fmt"

	"github.com/Fhwang0926/m-waf/internal/policybundle"
)

// syncBundlePolicySources imports only verified CRS source artifacts. Creating
// or publishing a system policy is an explicit Manager administrator action.
func (s *Server) syncBundlePolicySources(ctx context.Context) error {
	if s.catalog == nil {
		return nil
	}
	for _, source := range s.catalog.PolicySources() {
		indexedSource, index, ok := s.catalog.PolicySource(source.ID)
		if !ok {
			return fmt.Errorf("CI CRS source %s is missing its Rule index", source.ID)
		}
		if !indexedSource.TagSignatureVerified || indexedSource.TagObjectSHA == "" || indexedSource.ArtifactFormat != policybundle.FormatV3 {
			return fmt.Errorf("CI CRS source %s is not a signed self-contained release", source.ID)
		}
		if err := s.store.UpsertCRSReleaseIndex(ctx, indexedSource, index); err != nil {
			return err
		}
	}
	return nil
}
