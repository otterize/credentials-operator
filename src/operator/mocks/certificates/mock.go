// Code generated by MockGen. DO NOT EDIT.
// Source: controllers/secrets/types/secret_types.go

// Package mock_secretstypes is a generated GoMock package.
package mock_certificates

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	secretstypes "github.com/otterize/spire-integration-operator/src/controllers/secrets/types"
)

// MockCertificateDataGenerator is a mock of CertificateDataGenerator interface.
type MockCertificateDataGenerator struct {
	ctrl     *gomock.Controller
	recorder *MockCertificateDataGeneratorMockRecorder
}

// MockCertificateDataGeneratorMockRecorder is the mock recorder for MockCertificateDataGenerator.
type MockCertificateDataGeneratorMockRecorder struct {
	mock *MockCertificateDataGenerator
}

// NewMockCertificateDataGenerator creates a new mock instance.
func NewMockCertificateDataGenerator(ctrl *gomock.Controller) *MockCertificateDataGenerator {
	mock := &MockCertificateDataGenerator{ctrl: ctrl}
	mock.recorder = &MockCertificateDataGeneratorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCertificateDataGenerator) EXPECT() *MockCertificateDataGeneratorMockRecorder {
	return m.recorder
}

// GenerateJKS mocks base method.
func (m *MockCertificateDataGenerator) GenerateJKS(ctx context.Context, entryID, password string) (secretstypes.JKSCert, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateJKS", ctx, entryID, password)
	ret0, _ := ret[0].(secretstypes.JKSCert)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GenerateJKS indicates an expected call of GenerateJKS.
func (mr *MockCertificateDataGeneratorMockRecorder) GenerateJKS(ctx, entryID, password interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateJKS", reflect.TypeOf((*MockCertificateDataGenerator)(nil).GenerateJKS), ctx, entryID, password)
}

// GeneratePem mocks base method.
func (m *MockCertificateDataGenerator) GeneratePem(ctx context.Context, entryID string) (secretstypes.PemCert, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GeneratePem", ctx, entryID)
	ret0, _ := ret[0].(secretstypes.PemCert)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GeneratePem indicates an expected call of GeneratePem.
func (mr *MockCertificateDataGeneratorMockRecorder) GeneratePem(ctx, entryID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GeneratePem", reflect.TypeOf((*MockCertificateDataGenerator)(nil).GeneratePem), ctx, entryID)
}
