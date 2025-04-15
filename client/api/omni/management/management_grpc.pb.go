// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v4.24.4
// source: omni/management/management.proto

package management

import (
	context "context"

	common "github.com/siderolabs/talos/pkg/machinery/api/common"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	ManagementService_Kubeconfig_FullMethodName                 = "/management.ManagementService/Kubeconfig"
	ManagementService_Talosconfig_FullMethodName                = "/management.ManagementService/Talosconfig"
	ManagementService_Omniconfig_FullMethodName                 = "/management.ManagementService/Omniconfig"
	ManagementService_MachineLogs_FullMethodName                = "/management.ManagementService/MachineLogs"
	ManagementService_ValidateConfig_FullMethodName             = "/management.ManagementService/ValidateConfig"
	ManagementService_ValidateJSONSchema_FullMethodName         = "/management.ManagementService/ValidateJSONSchema"
	ManagementService_CreateServiceAccount_FullMethodName       = "/management.ManagementService/CreateServiceAccount"
	ManagementService_RenewServiceAccount_FullMethodName        = "/management.ManagementService/RenewServiceAccount"
	ManagementService_ListServiceAccounts_FullMethodName        = "/management.ManagementService/ListServiceAccounts"
	ManagementService_DestroyServiceAccount_FullMethodName      = "/management.ManagementService/DestroyServiceAccount"
	ManagementService_KubernetesUpgradePreChecks_FullMethodName = "/management.ManagementService/KubernetesUpgradePreChecks"
	ManagementService_KubernetesSyncManifests_FullMethodName    = "/management.ManagementService/KubernetesSyncManifests"
	ManagementService_CreateSchematic_FullMethodName            = "/management.ManagementService/CreateSchematic"
	ManagementService_GetSupportBundle_FullMethodName           = "/management.ManagementService/GetSupportBundle"
	ManagementService_ReadAuditLog_FullMethodName               = "/management.ManagementService/ReadAuditLog"
)

// ManagementServiceClient is the client API for ManagementService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ManagementServiceClient interface {
	Kubeconfig(ctx context.Context, in *KubeconfigRequest, opts ...grpc.CallOption) (*KubeconfigResponse, error)
	Talosconfig(ctx context.Context, in *TalosconfigRequest, opts ...grpc.CallOption) (*TalosconfigResponse, error)
	Omniconfig(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*OmniconfigResponse, error)
	MachineLogs(ctx context.Context, in *MachineLogsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[common.Data], error)
	ValidateConfig(ctx context.Context, in *ValidateConfigRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	ValidateJSONSchema(ctx context.Context, in *ValidateJsonSchemaRequest, opts ...grpc.CallOption) (*ValidateJsonSchemaResponse, error)
	CreateServiceAccount(ctx context.Context, in *CreateServiceAccountRequest, opts ...grpc.CallOption) (*CreateServiceAccountResponse, error)
	RenewServiceAccount(ctx context.Context, in *RenewServiceAccountRequest, opts ...grpc.CallOption) (*RenewServiceAccountResponse, error)
	ListServiceAccounts(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*ListServiceAccountsResponse, error)
	DestroyServiceAccount(ctx context.Context, in *DestroyServiceAccountRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	KubernetesUpgradePreChecks(ctx context.Context, in *KubernetesUpgradePreChecksRequest, opts ...grpc.CallOption) (*KubernetesUpgradePreChecksResponse, error)
	KubernetesSyncManifests(ctx context.Context, in *KubernetesSyncManifestRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[KubernetesSyncManifestResponse], error)
	CreateSchematic(ctx context.Context, in *CreateSchematicRequest, opts ...grpc.CallOption) (*CreateSchematicResponse, error)
	GetSupportBundle(ctx context.Context, in *GetSupportBundleRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[GetSupportBundleResponse], error)
	ReadAuditLog(ctx context.Context, in *ReadAuditLogRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[ReadAuditLogResponse], error)
}

type managementServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewManagementServiceClient(cc grpc.ClientConnInterface) ManagementServiceClient {
	return &managementServiceClient{cc}
}

func (c *managementServiceClient) Kubeconfig(ctx context.Context, in *KubeconfigRequest, opts ...grpc.CallOption) (*KubeconfigResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(KubeconfigResponse)
	err := c.cc.Invoke(ctx, ManagementService_Kubeconfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementServiceClient) Talosconfig(ctx context.Context, in *TalosconfigRequest, opts ...grpc.CallOption) (*TalosconfigResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(TalosconfigResponse)
	err := c.cc.Invoke(ctx, ManagementService_Talosconfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementServiceClient) Omniconfig(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*OmniconfigResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(OmniconfigResponse)
	err := c.cc.Invoke(ctx, ManagementService_Omniconfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementServiceClient) MachineLogs(ctx context.Context, in *MachineLogsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[common.Data], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ManagementService_ServiceDesc.Streams[0], ManagementService_MachineLogs_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[MachineLogsRequest, common.Data]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ManagementService_MachineLogsClient = grpc.ServerStreamingClient[common.Data]

func (c *managementServiceClient) ValidateConfig(ctx context.Context, in *ValidateConfigRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, ManagementService_ValidateConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementServiceClient) ValidateJSONSchema(ctx context.Context, in *ValidateJsonSchemaRequest, opts ...grpc.CallOption) (*ValidateJsonSchemaResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ValidateJsonSchemaResponse)
	err := c.cc.Invoke(ctx, ManagementService_ValidateJSONSchema_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementServiceClient) CreateServiceAccount(ctx context.Context, in *CreateServiceAccountRequest, opts ...grpc.CallOption) (*CreateServiceAccountResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreateServiceAccountResponse)
	err := c.cc.Invoke(ctx, ManagementService_CreateServiceAccount_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementServiceClient) RenewServiceAccount(ctx context.Context, in *RenewServiceAccountRequest, opts ...grpc.CallOption) (*RenewServiceAccountResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(RenewServiceAccountResponse)
	err := c.cc.Invoke(ctx, ManagementService_RenewServiceAccount_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementServiceClient) ListServiceAccounts(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*ListServiceAccountsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListServiceAccountsResponse)
	err := c.cc.Invoke(ctx, ManagementService_ListServiceAccounts_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementServiceClient) DestroyServiceAccount(ctx context.Context, in *DestroyServiceAccountRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, ManagementService_DestroyServiceAccount_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementServiceClient) KubernetesUpgradePreChecks(ctx context.Context, in *KubernetesUpgradePreChecksRequest, opts ...grpc.CallOption) (*KubernetesUpgradePreChecksResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(KubernetesUpgradePreChecksResponse)
	err := c.cc.Invoke(ctx, ManagementService_KubernetesUpgradePreChecks_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementServiceClient) KubernetesSyncManifests(ctx context.Context, in *KubernetesSyncManifestRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[KubernetesSyncManifestResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ManagementService_ServiceDesc.Streams[1], ManagementService_KubernetesSyncManifests_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[KubernetesSyncManifestRequest, KubernetesSyncManifestResponse]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ManagementService_KubernetesSyncManifestsClient = grpc.ServerStreamingClient[KubernetesSyncManifestResponse]

func (c *managementServiceClient) CreateSchematic(ctx context.Context, in *CreateSchematicRequest, opts ...grpc.CallOption) (*CreateSchematicResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreateSchematicResponse)
	err := c.cc.Invoke(ctx, ManagementService_CreateSchematic_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *managementServiceClient) GetSupportBundle(ctx context.Context, in *GetSupportBundleRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[GetSupportBundleResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ManagementService_ServiceDesc.Streams[2], ManagementService_GetSupportBundle_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[GetSupportBundleRequest, GetSupportBundleResponse]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ManagementService_GetSupportBundleClient = grpc.ServerStreamingClient[GetSupportBundleResponse]

func (c *managementServiceClient) ReadAuditLog(ctx context.Context, in *ReadAuditLogRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[ReadAuditLogResponse], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &ManagementService_ServiceDesc.Streams[3], ManagementService_ReadAuditLog_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[ReadAuditLogRequest, ReadAuditLogResponse]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ManagementService_ReadAuditLogClient = grpc.ServerStreamingClient[ReadAuditLogResponse]

// ManagementServiceServer is the server API for ManagementService service.
// All implementations must embed UnimplementedManagementServiceServer
// for forward compatibility.
type ManagementServiceServer interface {
	Kubeconfig(context.Context, *KubeconfigRequest) (*KubeconfigResponse, error)
	Talosconfig(context.Context, *TalosconfigRequest) (*TalosconfigResponse, error)
	Omniconfig(context.Context, *emptypb.Empty) (*OmniconfigResponse, error)
	MachineLogs(*MachineLogsRequest, grpc.ServerStreamingServer[common.Data]) error
	ValidateConfig(context.Context, *ValidateConfigRequest) (*emptypb.Empty, error)
	ValidateJSONSchema(context.Context, *ValidateJsonSchemaRequest) (*ValidateJsonSchemaResponse, error)
	CreateServiceAccount(context.Context, *CreateServiceAccountRequest) (*CreateServiceAccountResponse, error)
	RenewServiceAccount(context.Context, *RenewServiceAccountRequest) (*RenewServiceAccountResponse, error)
	ListServiceAccounts(context.Context, *emptypb.Empty) (*ListServiceAccountsResponse, error)
	DestroyServiceAccount(context.Context, *DestroyServiceAccountRequest) (*emptypb.Empty, error)
	KubernetesUpgradePreChecks(context.Context, *KubernetesUpgradePreChecksRequest) (*KubernetesUpgradePreChecksResponse, error)
	KubernetesSyncManifests(*KubernetesSyncManifestRequest, grpc.ServerStreamingServer[KubernetesSyncManifestResponse]) error
	CreateSchematic(context.Context, *CreateSchematicRequest) (*CreateSchematicResponse, error)
	GetSupportBundle(*GetSupportBundleRequest, grpc.ServerStreamingServer[GetSupportBundleResponse]) error
	ReadAuditLog(*ReadAuditLogRequest, grpc.ServerStreamingServer[ReadAuditLogResponse]) error
	mustEmbedUnimplementedManagementServiceServer()
}

// UnimplementedManagementServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedManagementServiceServer struct{}

func (UnimplementedManagementServiceServer) Kubeconfig(context.Context, *KubeconfigRequest) (*KubeconfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Kubeconfig not implemented")
}
func (UnimplementedManagementServiceServer) Talosconfig(context.Context, *TalosconfigRequest) (*TalosconfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Talosconfig not implemented")
}
func (UnimplementedManagementServiceServer) Omniconfig(context.Context, *emptypb.Empty) (*OmniconfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Omniconfig not implemented")
}
func (UnimplementedManagementServiceServer) MachineLogs(*MachineLogsRequest, grpc.ServerStreamingServer[common.Data]) error {
	return status.Errorf(codes.Unimplemented, "method MachineLogs not implemented")
}
func (UnimplementedManagementServiceServer) ValidateConfig(context.Context, *ValidateConfigRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ValidateConfig not implemented")
}
func (UnimplementedManagementServiceServer) ValidateJSONSchema(context.Context, *ValidateJsonSchemaRequest) (*ValidateJsonSchemaResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ValidateJSONSchema not implemented")
}
func (UnimplementedManagementServiceServer) CreateServiceAccount(context.Context, *CreateServiceAccountRequest) (*CreateServiceAccountResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateServiceAccount not implemented")
}
func (UnimplementedManagementServiceServer) RenewServiceAccount(context.Context, *RenewServiceAccountRequest) (*RenewServiceAccountResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RenewServiceAccount not implemented")
}
func (UnimplementedManagementServiceServer) ListServiceAccounts(context.Context, *emptypb.Empty) (*ListServiceAccountsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListServiceAccounts not implemented")
}
func (UnimplementedManagementServiceServer) DestroyServiceAccount(context.Context, *DestroyServiceAccountRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DestroyServiceAccount not implemented")
}
func (UnimplementedManagementServiceServer) KubernetesUpgradePreChecks(context.Context, *KubernetesUpgradePreChecksRequest) (*KubernetesUpgradePreChecksResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method KubernetesUpgradePreChecks not implemented")
}
func (UnimplementedManagementServiceServer) KubernetesSyncManifests(*KubernetesSyncManifestRequest, grpc.ServerStreamingServer[KubernetesSyncManifestResponse]) error {
	return status.Errorf(codes.Unimplemented, "method KubernetesSyncManifests not implemented")
}
func (UnimplementedManagementServiceServer) CreateSchematic(context.Context, *CreateSchematicRequest) (*CreateSchematicResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateSchematic not implemented")
}
func (UnimplementedManagementServiceServer) GetSupportBundle(*GetSupportBundleRequest, grpc.ServerStreamingServer[GetSupportBundleResponse]) error {
	return status.Errorf(codes.Unimplemented, "method GetSupportBundle not implemented")
}
func (UnimplementedManagementServiceServer) ReadAuditLog(*ReadAuditLogRequest, grpc.ServerStreamingServer[ReadAuditLogResponse]) error {
	return status.Errorf(codes.Unimplemented, "method ReadAuditLog not implemented")
}
func (UnimplementedManagementServiceServer) mustEmbedUnimplementedManagementServiceServer() {}
func (UnimplementedManagementServiceServer) testEmbeddedByValue()                           {}

// UnsafeManagementServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ManagementServiceServer will
// result in compilation errors.
type UnsafeManagementServiceServer interface {
	mustEmbedUnimplementedManagementServiceServer()
}

func RegisterManagementServiceServer(s grpc.ServiceRegistrar, srv ManagementServiceServer) {
	// If the following call pancis, it indicates UnimplementedManagementServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&ManagementService_ServiceDesc, srv)
}

func _ManagementService_Kubeconfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(KubeconfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServiceServer).Kubeconfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ManagementService_Kubeconfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServiceServer).Kubeconfig(ctx, req.(*KubeconfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ManagementService_Talosconfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TalosconfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServiceServer).Talosconfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ManagementService_Talosconfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServiceServer).Talosconfig(ctx, req.(*TalosconfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ManagementService_Omniconfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServiceServer).Omniconfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ManagementService_Omniconfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServiceServer).Omniconfig(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _ManagementService_MachineLogs_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(MachineLogsRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ManagementServiceServer).MachineLogs(m, &grpc.GenericServerStream[MachineLogsRequest, common.Data]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ManagementService_MachineLogsServer = grpc.ServerStreamingServer[common.Data]

func _ManagementService_ValidateConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ValidateConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServiceServer).ValidateConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ManagementService_ValidateConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServiceServer).ValidateConfig(ctx, req.(*ValidateConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ManagementService_ValidateJSONSchema_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ValidateJsonSchemaRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServiceServer).ValidateJSONSchema(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ManagementService_ValidateJSONSchema_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServiceServer).ValidateJSONSchema(ctx, req.(*ValidateJsonSchemaRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ManagementService_CreateServiceAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateServiceAccountRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServiceServer).CreateServiceAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ManagementService_CreateServiceAccount_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServiceServer).CreateServiceAccount(ctx, req.(*CreateServiceAccountRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ManagementService_RenewServiceAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RenewServiceAccountRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServiceServer).RenewServiceAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ManagementService_RenewServiceAccount_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServiceServer).RenewServiceAccount(ctx, req.(*RenewServiceAccountRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ManagementService_ListServiceAccounts_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServiceServer).ListServiceAccounts(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ManagementService_ListServiceAccounts_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServiceServer).ListServiceAccounts(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _ManagementService_DestroyServiceAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DestroyServiceAccountRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServiceServer).DestroyServiceAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ManagementService_DestroyServiceAccount_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServiceServer).DestroyServiceAccount(ctx, req.(*DestroyServiceAccountRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ManagementService_KubernetesUpgradePreChecks_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(KubernetesUpgradePreChecksRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServiceServer).KubernetesUpgradePreChecks(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ManagementService_KubernetesUpgradePreChecks_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServiceServer).KubernetesUpgradePreChecks(ctx, req.(*KubernetesUpgradePreChecksRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ManagementService_KubernetesSyncManifests_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(KubernetesSyncManifestRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ManagementServiceServer).KubernetesSyncManifests(m, &grpc.GenericServerStream[KubernetesSyncManifestRequest, KubernetesSyncManifestResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ManagementService_KubernetesSyncManifestsServer = grpc.ServerStreamingServer[KubernetesSyncManifestResponse]

func _ManagementService_CreateSchematic_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateSchematicRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManagementServiceServer).CreateSchematic(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ManagementService_CreateSchematic_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManagementServiceServer).CreateSchematic(ctx, req.(*CreateSchematicRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ManagementService_GetSupportBundle_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetSupportBundleRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ManagementServiceServer).GetSupportBundle(m, &grpc.GenericServerStream[GetSupportBundleRequest, GetSupportBundleResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ManagementService_GetSupportBundleServer = grpc.ServerStreamingServer[GetSupportBundleResponse]

func _ManagementService_ReadAuditLog_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ReadAuditLogRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ManagementServiceServer).ReadAuditLog(m, &grpc.GenericServerStream[ReadAuditLogRequest, ReadAuditLogResponse]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type ManagementService_ReadAuditLogServer = grpc.ServerStreamingServer[ReadAuditLogResponse]

// ManagementService_ServiceDesc is the grpc.ServiceDesc for ManagementService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ManagementService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "management.ManagementService",
	HandlerType: (*ManagementServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Kubeconfig",
			Handler:    _ManagementService_Kubeconfig_Handler,
		},
		{
			MethodName: "Talosconfig",
			Handler:    _ManagementService_Talosconfig_Handler,
		},
		{
			MethodName: "Omniconfig",
			Handler:    _ManagementService_Omniconfig_Handler,
		},
		{
			MethodName: "ValidateConfig",
			Handler:    _ManagementService_ValidateConfig_Handler,
		},
		{
			MethodName: "ValidateJSONSchema",
			Handler:    _ManagementService_ValidateJSONSchema_Handler,
		},
		{
			MethodName: "CreateServiceAccount",
			Handler:    _ManagementService_CreateServiceAccount_Handler,
		},
		{
			MethodName: "RenewServiceAccount",
			Handler:    _ManagementService_RenewServiceAccount_Handler,
		},
		{
			MethodName: "ListServiceAccounts",
			Handler:    _ManagementService_ListServiceAccounts_Handler,
		},
		{
			MethodName: "DestroyServiceAccount",
			Handler:    _ManagementService_DestroyServiceAccount_Handler,
		},
		{
			MethodName: "KubernetesUpgradePreChecks",
			Handler:    _ManagementService_KubernetesUpgradePreChecks_Handler,
		},
		{
			MethodName: "CreateSchematic",
			Handler:    _ManagementService_CreateSchematic_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "MachineLogs",
			Handler:       _ManagementService_MachineLogs_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "KubernetesSyncManifests",
			Handler:       _ManagementService_KubernetesSyncManifests_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "GetSupportBundle",
			Handler:       _ManagementService_GetSupportBundle_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "ReadAuditLog",
			Handler:       _ManagementService_ReadAuditLog_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "omni/management/management.proto",
}
