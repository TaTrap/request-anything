package models

import pkgmodels "github.com/TaTrap/request-anything/pkg/models"

const (
	SchemaFixture        = pkgmodels.SchemaFixture
	SchemaAnalyze        = pkgmodels.SchemaAnalyze
	SchemaBridge         = pkgmodels.SchemaBridge
	SchemaReport         = pkgmodels.SchemaReport
	FidelityLosslessWire = pkgmodels.FidelityLosslessWire
	FidelityLossyHAR     = pkgmodels.FidelityLossyHAR
	FidelityHookDump     = pkgmodels.FidelityHookDump
	CookieSingleHeader   = pkgmodels.CookieSingleHeader
	CookieH2Crumbs       = pkgmodels.CookieH2Crumbs
)

type CaptureFidelity = pkgmodels.CaptureFidelity
type CookieWireMode = pkgmodels.CookieWireMode
type JSONStyle = pkgmodels.JSONStyle
type HeaderKV = pkgmodels.HeaderKV
type QueryParam = pkgmodels.QueryParam
type TransportMeta = pkgmodels.TransportMeta
type WireBody = pkgmodels.WireBody
type WireRequest = pkgmodels.WireRequest
type WireResponse = pkgmodels.WireResponse
type GoldenFixture = pkgmodels.GoldenFixture
type FieldRule = pkgmodels.FieldRule
type PositiveAssertion = pkgmodels.PositiveAssertion
type ContractSpec = pkgmodels.ContractSpec
type DiffFinding = pkgmodels.DiffFinding
type DiffResult = pkgmodels.DiffResult
type KnownDiffEntry = pkgmodels.KnownDiffEntry
type Trend = pkgmodels.Trend
type UnitManifest = pkgmodels.UnitManifest
type Check = pkgmodels.Check
type GateOutcome = pkgmodels.GateOutcome
