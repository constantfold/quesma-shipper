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

// Keeps upload's copy of the metadata allowlist in step with controlplane's tags.

func TestMetadataNamesMatchControlPlane(t *testing.T) {
	var tags []string
	for _, f := range reflect.VisibleFields(reflect.TypeOf(controlplane.UploadMetadata{})) {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		tags = append(tags, name)
		mapped, _, err := uploadMetadata(map[string]string{name: name})
		require.NoError(t, err)
		require.Equal(t, name, reflect.ValueOf(mapped).FieldByName(f.Name).String())
	}
	require.Truef(t, slices.Equal(tags, upload.MetadataNames), "upload.MetadataNames drifted from controlplane.UploadMetadata tags:\n  tags:  %v\n  names: %v", tags, upload.MetadataNames)
}
