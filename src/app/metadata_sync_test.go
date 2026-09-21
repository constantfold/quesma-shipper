package app

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/QuesmaOrg/quesma-shipper/internal/controlplane"
	"github.com/QuesmaOrg/quesma-shipper/internal/upload"
)

// Pins upload's deliberate copy of the metadata allowlist to controlplane's tags; only app may
// import both packages.

func TestMetadataNamesMatchControlPlane(t *testing.T) {
	var tags []string
	for _, f := range reflect.VisibleFields(reflect.TypeOf(controlplane.UploadMetadata{})) {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		tags = append(tags, name)
	}
	require.Truef(t, slices.Equal(tags, upload.MetadataNames), "upload.MetadataNames drifted from controlplane.UploadMetadata tags:\n  tags:  %v\n  names: %v", tags, upload.MetadataNames)
}
