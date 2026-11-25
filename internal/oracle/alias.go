package oracle

import (
	"context"

	"github.com/TaTrap/request-anything/pkg/models"
	pkgoracle "github.com/TaTrap/request-anything/pkg/oracle"
)

type SessionHandle = pkgoracle.SessionHandle
type SessionConfig = pkgoracle.SessionConfig
type NativeSnapshot = pkgoracle.NativeSnapshot
type SignInput = pkgoracle.SignInput
type SignOutput = pkgoracle.SignOutput
type AsyncPacket = pkgoracle.AsyncPacket
type OracleHealth = pkgoracle.OracleHealth
type DeliverResult = pkgoracle.DeliverResult
type NativeOracle = pkgoracle.NativeOracle
type SerializedOracle = pkgoracle.SerializedOracle
type MockOracle = pkgoracle.MockOracle
type RPCClient = pkgoracle.RPCClient

func NewSerializedOracle(inner NativeOracle) *SerializedOracle {
	return pkgoracle.NewSerializedOracle(inner)
}

func NewMockOracle() *MockOracle {
	return pkgoracle.NewMockOracle()
}

func NewRPCClient(endpoint string) *RPCClient {
	return pkgoracle.NewRPCClient(endpoint)
}

func VerifySignatureRule(ctx context.Context, rule models.FieldRule, expectedVal, actualVal string, actualReq *models.WireRequest) *models.DiffFinding {
	return pkgoracle.VerifySignatureRule(ctx, rule, expectedVal, actualVal, actualReq)
}
