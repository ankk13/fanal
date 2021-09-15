package image

import (
	"context"
	"encoding/json"
	"image"
	"io"
	"os"
	"reflect"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/config/scanner"
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/walker"
)

const (
	parallel = 5
)

var (
	defaultDisabledAnalyzers = []analyzer.Type{
		// Do not scan go.sum in container images, only scan go binaries
		analyzer.TypeGoMod,

		// Do not scan requirements.txt, Pipfile.lock and poetry.lock in container images, only scan egg and wheel
		analyzer.TypePip,
		analyzer.TypePipenv,
		analyzer.TypePoetry,

		// Do not scan Gemfile.lock in container images, only scan .gemspec
		analyzer.TypeBundler,

		// Do not scan package-lock.json and yarn.lock in container images, only scan package.json
		analyzer.TypeNpmPkgLock,
		analyzer.TypeYarn,
	}

	defaultDisabledHooks []hook.Type
)

type Artifact struct {
	image               image.Image
	caches              []cache.ArtifactCache
	analyzer            analyzer.Analyzer
	hookManager         hook.Manager
	scanner             scanner.Scanner
	configScannerOption config.ScannerOption
}

type layerkeyDiffIdMap map[string]string
type cacheLayerKeyMap map[types.CacheType]layerkeyDiffIdMap

func NewArtifact(img image.Image, c []cache.ArtifactCache, disabledAnalyzers []analyzer.Type, disabledHooks []hook.Type, opt config.ScannerOption) (artifact.Artifact, error) {
	// Register config analyzers
	if err := config.RegisterConfigAnalyzers(opt.FilePatterns); err != nil {
		return nil, xerrors.Errorf("config scanner error: %w", err)
	}

	s, err := scanner.New("", opt.Namespaces, opt.PolicyPaths, opt.DataPaths, opt.Trace)
	if err != nil {
		return nil, xerrors.Errorf("scanner error: %w", err)
	}

	disabledAnalyzers = append(disabledAnalyzers, defaultDisabledAnalyzers...)
	disabledHooks = append(disabledHooks, defaultDisabledHooks...)

	return Artifact{
		image:               img,
		caches:              c,
		analyzer:            analyzer.NewAnalyzer(disabled),
		scanner:             s,
		configScannerOption: opt,
	}, nil
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	imageID, err := a.image.ID()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get the image ID: %w", err)
	}

	diffIDs, err := a.image.LayerIDs()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get layer IDs: %w", err)
	}

	configFile, err := a.image.ConfigFile()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get the image's config file: %w", err)
	}

	// Debug
	log.Logger.Debugf("Image ID: %s", imageID)
	log.Logger.Debugf("Diff IDs: %v", diffIDs)

	var finalImageKey string
	var missingImageKey string
	var missingDiffsMap = map[string]struct{}{}

	cacheLayerKeyMap := cacheLayerKeyMap{}

	// This stores only layerKeys in sequence, for ArtifactReference
	cacheLayerKeys := map[types.CacheType][]string{}

	for _, c := range a.caches {

		// Convert image ID and layer IDs to cache keys
		imageKey, layerKeys, layerKeyMap, err := a.calcCacheKeys(imageID, diffIDs, c.Type())
		if err != nil {
			return types.ArtifactReference{}, err
		}
		cacheLayerKeys[c.Type()] = layerKeys
		cacheLayerKeyMap[c.Type()] = layerKeyMap
		// Image key will be same irrespective of cache
		if finalImageKey != "" {
			if finalImageKey != imageKey {
				return types.ArtifactReference{}, xerrors.Errorf("Image key for each cache needs to be same")
			}
		} else {
			finalImageKey = imageKey
		}

		var missingLayers []string
		if c.Type() == types.BuiltInCache {
			missingImage, missingLayerkeys, err := c.MissingBlobs(imageKey, layerKeys)
			if err != nil {
				return types.ArtifactReference{}, xerrors.Errorf("unable to get missing layers: %w", err)
			}
			if missingImage {
				missingImageKey = imageKey
				log.Logger.Debugf("Missing image ID: %s", imageID)
			} else {
				missingImageKey = ""
			}
			missingLayers = missingLayerkeys
		} else {
			_, missingLayers, err = c.MissingBlobs(imageKey, layerKeys)
			if err != nil {
				return types.ArtifactReference{}, xerrors.Errorf("unable to get missing layers: %w", err)
			}
		}

		// Collect unique diffIds for all missing layers
		for _, layerKey := range missingLayers {
			missingDiffsMap[layerKeyMap[layerKey]] = struct{}{}
		}
	}

	if err = a.inspect(ctx, missingImageKey, missingDiffsMap, cacheLayerKeyMap); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("analyze error: %w", err)
	}

	return types.ArtifactReference{
		Name:    a.image.Name(),
		Type:    types.ArtifactContainerImage,
		ID:      finalImageKey,
		BlobIDs: cacheLayerKeys,
		ImageMetadata: types.ImageMetadata{
			ID:          imageID,
			DiffIDs:     diffIDs,
			RepoTags:    a.image.RepoTags(),
			RepoDigests: a.image.RepoDigests(),
			ConfigFile:  *configFile,
		},
	}, nil
}

func (a Artifact) calcCacheKeys(imageID string, diffIDs []string, cacheType types.CacheType) (string, []string, map[string]string, error) {
	// Pass an empty config scanner option so that the cache key can be the same, even when policies are updated.
	imageKey, err := cache.CalcKey(imageID, a.analyzer.ImageConfigAnalyzerVersions(), nil, &config.ScannerOption{})
	if err != nil {
		return "", nil, nil, err
	}

	layerKeyMap := map[string]string{}
	hookVersions := a.hookManager.Versions()
	var layerKeys []string
	for _, diffID := range diffIDs {
		blobKey, err := cache.CalcKey(diffID, a.analyzer.AnalyzerVersions(cacheType), hookVersions, &a.configScannerOption)
		if err != nil {
			return "", nil, nil, err
		}
		layerKeys = append(layerKeys, blobKey)
		layerKeyMap[blobKey] = diffID
	}
	return imageKey, layerKeys, layerKeyMap, nil
}

func (a Artifact) inspect(ctx context.Context, missingImage string, diffIDs map[string]struct{}, layerKeyMap cacheLayerKeyMap) error {
	done := make(chan struct{})
	errCh := make(chan error)

	var osFound types.OS
	for diffID, _ := range diffIDs {
		go func(ctx context.Context, diffID string) {
			layerInfo, err := a.inspectLayer(ctx, diffID)
			if err != nil {
				errCh <- xerrors.Errorf("failed to analyze layer: %s : %w", diffID, err)
				return
			}
			for _, cache := range a.caches {
				for layerKey, diffId := range layerKeyMap[cache.Type()] {
					if diffID == diffId {
						if err = cache.PutBlob(layerKey, layerInfo[cache.Type()]); err != nil {
							errCh <- xerrors.Errorf("failed to store layer: %s in cache: %w", layerKey, err)
							return
						}
						break
					}
				}

				if layerInfo[cache.Type()].OS != nil {
					osFound = *layerInfo[cache.Type()].OS
				}
			}

			done <- struct{}{}
		}(ctx, diffID)
	}

	for range diffIDs {
		select {
		case <-done:
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return xerrors.Errorf("timeout: %w", ctx.Err())
		}
	}
	for _, cache := range a.caches {
		if missingImage != "" && cache.Type() == types.BuiltInCache {
			log.Logger.Debugf("Missing image cache: %s", missingImage)
			if err := a.inspectConfig(missingImage, osFound, cache); err != nil {
				return xerrors.Errorf("unable to analyze config: %w", err)
			}
		}
	}

	return nil

}

func (a Artifact) inspectLayer(ctx context.Context, diffID string) (map[types.CacheType]types.BlobInfo, error) {
	log.Logger.Debugf("Missing diff ID: %s", diffID)
	layerInfo := map[types.CacheType]types.BlobInfo{}
	layerDigest, cr, err := a.uncompressedLayer(diffID)
	if err != nil {
		return nil, xerrors.Errorf("unable to get uncompressed layer %s: %w", diffID, err)
	}

	var wg sync.WaitGroup
	var resultMap = map[types.CacheType]*analyzer.AnalysisResult{}
	for _, cache := range a.caches {
		resultMap[cache.Type()] = new(analyzer.AnalysisResult)
	}
	limit := semaphore.NewWeighted(parallel)
	opqDirs, whFiles, err := walker.WalkLayerTar(cr, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, resultMap, filePath, info, opener); err != nil {
			return xerrors.Errorf("failed to analyze %s: %w", filePath, err)
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	for cache, result := range resultMap {
		// Sort the analysis result for consistent results
		result.Sort()

		// Scan config files
		misconfs, err := a.scanner.ScanConfigs(ctx, result.Configs)
		if err != nil {
			return nil, xerrors.Errorf("config scan error: %w", err)
		}
		blobInfo := types.BlobInfo{
			SchemaVersion:     types.BlobJSONSchemaVersion,
			Digest:            layerDigest,
			DiffID:            diffID,
			Misconfigurations: misconfs,
			OpaqueDirs:        opqDirs,
			WhiteoutFiles:     whFiles,
			OS:                result.OS,
			PackageInfos:      result.PackageInfos,
			Applications:      result.Applications,
			CustomResources:   result.CustomResources,
		}
		layerInfo[cache] = blobInfo
	}

	return layerInfo, nil
}

func (a Artifact) uncompressedLayer(diffID string) (string, io.Reader, error) {
	// diffID is a hash of the uncompressed layer
	h, err := v1.NewHash(diffID)
	if err != nil {
		return "", nil, xerrors.Errorf("invalid layer ID (%s): %w", diffID, err)
	}

	layer, err := a.image.LayerByDiffID(h)
	if err != nil {
		return "", nil, xerrors.Errorf("failed to get the layer (%s): %w", diffID, err)
	}

	// digest is a hash of the compressed layer
	var digest string
	if a.isCompressed(layer) {
		d, err := layer.Digest()
		if err != nil {
			return "", nil, xerrors.Errorf("failed to get the digest (%s): %w", diffID, err)
		}
		digest = d.String()
	}

	r, err := layer.Uncompressed()
	if err != nil {
		return "", nil, xerrors.Errorf("failed to get the layer content (%s): %w", diffID, err)
	}
	return digest, r, nil
}

// ref. https://github.com/google/go-containerregistry/issues/701
func (a Artifact) isCompressed(l v1.Layer) bool {
	_, uncompressed := reflect.TypeOf(l).Elem().FieldByName("UncompressedLayer")
	return !uncompressed
}

func (a Artifact) inspectConfig(imageID string, osFound types.OS, cache cache.ArtifactCache) error {
	configBlob, err := a.image.ConfigBlob()
	if err != nil {
		return xerrors.Errorf("unable to get config blob: %w", err)
	}

	pkgs := a.analyzer.AnalyzeImageConfig(osFound, configBlob)

	var s1 v1.ConfigFile
	if err = json.Unmarshal(configBlob, &s1); err != nil {
		return xerrors.Errorf("json marshal error: %w", err)
	}

	info := types.ArtifactInfo{
		SchemaVersion:   types.ArtifactJSONSchemaVersion,
		Architecture:    s1.Architecture,
		Created:         s1.Created.Time,
		DockerVersion:   s1.DockerVersion,
		OS:              s1.OS,
		HistoryPackages: pkgs,
	}

	if err := cache.PutArtifact(imageID, info); err != nil {
		return xerrors.Errorf("failed to put image info into the cache: %w", err)
	}

	return nil
}
