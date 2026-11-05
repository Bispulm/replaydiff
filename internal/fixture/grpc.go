package fixture

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// descriptorSet is built from proto/orders.proto by `make proto`.
//
//go:embed proto/orders.binpb
var descriptorSet []byte

var (
	filesOnce sync.Once
	files     *protoregistry.Files
)

// DescriptorSet returns the compiled descriptors for the fixture's gRPC service.
func DescriptorSet() []byte { return descriptorSet }

// Descriptors returns the fixture's schema. The fixture runs entirely from it, with no
// generated code, which is the same path replaydiff takes with a user's descriptor set.
func Descriptors() *protoregistry.Files {
	filesOnce.Do(func() {
		var set descriptorpb.FileDescriptorSet
		if err := proto.Unmarshal(descriptorSet, &set); err != nil {
			panic(fmt.Sprintf("fixture: embedded descriptor set is invalid: %v", err))
		}
		resolved, err := protodesc.NewFiles(&set)
		if err != nil {
			panic(fmt.Sprintf("fixture: embedded descriptor set is invalid: %v", err))
		}
		files = resolved
	})
	return files
}

const servicePackage = "fixture.orders.v1."

func newMessage(name string) *dynamicpb.Message {
	descriptor, err := Descriptors().FindDescriptorByName(protoreflect.FullName(servicePackage + name))
	if err != nil {
		panic(fmt.Sprintf("fixture: unknown message %s", name))
	}
	return dynamicpb.NewMessage(descriptor.(protoreflect.MessageDescriptor))
}

// fromJSON builds a message from a JSON value, which keeps the responses readable.
func fromJSON(name string, value map[string]any) (*dynamicpb.Message, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	message := newMessage(name)
	if err := protojson.Unmarshal(data, message); err != nil {
		return nil, err
	}
	return message, nil
}

// GRPCService is the fixture's gRPC counterpart. A Candidate variant carries the
// deliberate regressions listed in docs/fixtures.md.
type GRPCService struct {
	http      *Service
	requests  atomic.Int64
	mutations atomic.Int64
}

// NewGRPC returns a gRPC service for the given options.
func NewGRPC(opts Options) (*GRPCService, error) {
	service, err := New(opts)
	if err != nil {
		return nil, err
	}
	return &GRPCService{http: service}, nil
}

// Stats returns a snapshot of the request counters.
func (s *GRPCService) Stats() Stats {
	return Stats{Requests: s.requests.Load(), Mutations: s.mutations.Load()}
}

type unaryHandler func(ctx context.Context, request *dynamicpb.Message) (proto.Message, error)

func (s *GRPCService) unary(requestType string, handle unaryHandler) grpc.MethodHandler {
	return func(_ any, ctx context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
		s.requests.Add(1)
		request := newMessage(requestType)
		if err := decode(request); err != nil {
			return nil, err
		}
		return handle(ctx, request)
	}
}

// Server returns a gRPC server with the fixture's service registered.
func (s *GRPCService) Server() *grpc.Server {
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: servicePackage + "OrderService",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "GetOrder", Handler: s.unary("GetOrderRequest", s.getOrder)},
			{MethodName: "CreateOrder", Handler: s.unary("CreateOrderRequest", s.createOrder)},
			{MethodName: "GetCatalog", Handler: s.unary("GetCatalogRequest", s.getCatalog)},
		},
		Streams: []grpc.StreamDesc{
			{StreamName: "WatchOrders", ServerStreams: true, Handler: s.watchOrders},
		},
		Metadata: "orders.proto",
	}, s)
	return server
}

func (s *GRPCService) order(id string) map[string]any {
	order := map[string]any{
		"id":          id,
		"status":      "ORDER_STATUS_SHIPPED",
		"total_cents": "9007199254740993",
		"currency":    "USD",
		"customer":    map[string]any{"id": "cus-1", "email": "1@customers.example.test", "tier": "gold"},
		"items":       []any{map[string]any{"sku": "sku-1", "qty": 2}, map[string]any{"sku": "sku-2", "qty": 1}},
		"labels":      map[string]any{"region": "us-east", "channel": "web"},
		"card_last4":  "4242",
		"note":        "leave at the door",
		"checksum":    base64.StdEncoding.EncodeToString([]byte("checksum-1")),
		"server_time": now(),
		"request_id":  s.http.requestID(),
		"weight":      1.5,
		"shipment":    map[string]any{"carrier": "synthetic-post"},
		"tags":        []any{"gift", "fragile"},
	}
	if s.http.isCandidate() {
		// Deliberate regressions: an optional field and a message field go unset, the
		// oneof switches member, the enum changes, and one map entry is replaced by another.
		delete(order, "note")
		delete(order, "shipment")
		delete(order, "card_last4")
		order["invoice_id"] = "inv-1"
		order["status"] = "ORDER_STATUS_PENDING"
		order["labels"] = map[string]any{"channel": "web", "experiment": "b"}
	}
	return order
}

func (s *GRPCService) getOrder(_ context.Context, request *dynamicpb.Message) (proto.Message, error) {
	id := request.Get(request.Descriptor().Fields().ByName("id")).String()
	switch {
	case id == "ord-missing" && s.http.isCandidate():
		// Deliberate regression: an unknown order is now a server error.
		return nil, status.Error(codes.Internal, "lookup failed")
	case id == "ord-missing":
		return nil, status.Error(codes.NotFound, "no such order")
	case id == "ord-unavailable" && s.http.isCandidate():
		// Deliberate regression: a request that worked now fails.
		return nil, status.Error(codes.Unavailable, "temporarily unavailable")
	}
	return fromJSON("Order", s.order(id))
}

func (s *GRPCService) createOrder(_ context.Context, _ *dynamicpb.Message) (proto.Message, error) {
	s.mutations.Add(1)
	return fromJSON("Order", s.order("ord-new"))
}

// getCatalog is the control route: no variant introduces a regression here.
func (s *GRPCService) getCatalog(_ context.Context, _ *dynamicpb.Message) (proto.Message, error) {
	return fromJSON("Catalog", map[string]any{
		"skus":         []any{"sku-1", "sku-2", "sku-3"},
		"generated_at": now(),
		"request_id":   s.http.requestID(),
	})
}

func (s *GRPCService) watchOrders(_ any, stream grpc.ServerStream) error {
	s.requests.Add(1)
	request := newMessage("GetOrderRequest")
	if err := stream.RecvMsg(request); err != nil {
		return err
	}
	for i := range 3 {
		order, err := fromJSON("Order", s.order(fmt.Sprintf("ord-%d", i+1)))
		if err != nil {
			return err
		}
		if err := stream.SendMsg(order); err != nil {
			return err
		}
	}
	return nil
}
