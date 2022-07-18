package spireclient

//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -destination=mocks/controller-runtime/client/mock.go sigs.k8s.io/controller-runtime/pkg/client Client,Reader,Writer
//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -destination=mocks/spireclient/bundles/mock.go github.com/otterize/spifferize/src/spireclient/bundles Store
//go:generate go run github.com/golang/mock/mockgen@v1.6.0 -destination=mocks/spireclient/svids/mock.go github.com/otterize/spifferize/src/spireclient/svids Store
