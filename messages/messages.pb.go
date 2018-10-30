// Code generated by protoc-gen-go. DO NOT EDIT.
// source: messages.proto

package messages

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Message struct {
	// Types that are valid to be assigned to Type:
	//	*Message_Request
	//	*Message_Reply
	//	*Message_Prepare
	//	*Message_Commit
	Type                 isMessage_Type `protobuf_oneof:"type"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *Message) Reset()         { *m = Message{} }
func (m *Message) String() string { return proto.CompactTextString(m) }
func (*Message) ProtoMessage()    {}
func (*Message) Descriptor() ([]byte, []int) {
	return fileDescriptor_messages_0897251da7b8b1b0, []int{0}
}
func (m *Message) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Message.Unmarshal(m, b)
}
func (m *Message) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Message.Marshal(b, m, deterministic)
}
func (dst *Message) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Message.Merge(dst, src)
}
func (m *Message) XXX_Size() int {
	return xxx_messageInfo_Message.Size(m)
}
func (m *Message) XXX_DiscardUnknown() {
	xxx_messageInfo_Message.DiscardUnknown(m)
}

var xxx_messageInfo_Message proto.InternalMessageInfo

type isMessage_Type interface {
	isMessage_Type()
}

type Message_Request struct {
	Request *Request `protobuf:"bytes,1,opt,name=request,proto3,oneof"`
}
type Message_Reply struct {
	Reply *Reply `protobuf:"bytes,2,opt,name=reply,proto3,oneof"`
}
type Message_Prepare struct {
	Prepare *Prepare `protobuf:"bytes,3,opt,name=prepare,proto3,oneof"`
}
type Message_Commit struct {
	Commit *Commit `protobuf:"bytes,4,opt,name=commit,proto3,oneof"`
}

func (*Message_Request) isMessage_Type() {}
func (*Message_Reply) isMessage_Type()   {}
func (*Message_Prepare) isMessage_Type() {}
func (*Message_Commit) isMessage_Type()  {}

func (m *Message) GetType() isMessage_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (m *Message) GetRequest() *Request {
	if x, ok := m.GetType().(*Message_Request); ok {
		return x.Request
	}
	return nil
}

func (m *Message) GetReply() *Reply {
	if x, ok := m.GetType().(*Message_Reply); ok {
		return x.Reply
	}
	return nil
}

func (m *Message) GetPrepare() *Prepare {
	if x, ok := m.GetType().(*Message_Prepare); ok {
		return x.Prepare
	}
	return nil
}

func (m *Message) GetCommit() *Commit {
	if x, ok := m.GetType().(*Message_Commit); ok {
		return x.Commit
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Message) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Message_OneofMarshaler, _Message_OneofUnmarshaler, _Message_OneofSizer, []interface{}{
		(*Message_Request)(nil),
		(*Message_Reply)(nil),
		(*Message_Prepare)(nil),
		(*Message_Commit)(nil),
	}
}

func _Message_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Message)
	// type
	switch x := m.Type.(type) {
	case *Message_Request:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Request); err != nil {
			return err
		}
	case *Message_Reply:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Reply); err != nil {
			return err
		}
	case *Message_Prepare:
		b.EncodeVarint(3<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Prepare); err != nil {
			return err
		}
	case *Message_Commit:
		b.EncodeVarint(4<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Commit); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("Message.Type has unexpected type %T", x)
	}
	return nil
}

func _Message_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Message)
	switch tag {
	case 1: // type.request
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Request)
		err := b.DecodeMessage(msg)
		m.Type = &Message_Request{msg}
		return true, err
	case 2: // type.reply
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Reply)
		err := b.DecodeMessage(msg)
		m.Type = &Message_Reply{msg}
		return true, err
	case 3: // type.prepare
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Prepare)
		err := b.DecodeMessage(msg)
		m.Type = &Message_Prepare{msg}
		return true, err
	case 4: // type.commit
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Commit)
		err := b.DecodeMessage(msg)
		m.Type = &Message_Commit{msg}
		return true, err
	default:
		return false, nil
	}
}

func _Message_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Message)
	// type
	switch x := m.Type.(type) {
	case *Message_Request:
		s := proto.Size(x.Request)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Message_Reply:
		s := proto.Size(x.Reply)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Message_Prepare:
		s := proto.Size(x.Prepare)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Message_Commit:
		s := proto.Size(x.Commit)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type Request struct {
	Msg                  *Request_M `protobuf:"bytes,1,opt,name=msg,proto3" json:"msg,omitempty"`
	Signature            []byte     `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *Request) Reset()         { *m = Request{} }
func (m *Request) String() string { return proto.CompactTextString(m) }
func (*Request) ProtoMessage()    {}
func (*Request) Descriptor() ([]byte, []int) {
	return fileDescriptor_messages_0897251da7b8b1b0, []int{1}
}
func (m *Request) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Request.Unmarshal(m, b)
}
func (m *Request) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Request.Marshal(b, m, deterministic)
}
func (dst *Request) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Request.Merge(dst, src)
}
func (m *Request) XXX_Size() int {
	return xxx_messageInfo_Request.Size(m)
}
func (m *Request) XXX_DiscardUnknown() {
	xxx_messageInfo_Request.DiscardUnknown(m)
}

var xxx_messageInfo_Request proto.InternalMessageInfo

func (m *Request) GetMsg() *Request_M {
	if m != nil {
		return m.Msg
	}
	return nil
}

func (m *Request) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

type Request_M struct {
	ClientId             uint32   `protobuf:"varint,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	Seq                  uint64   `protobuf:"varint,2,opt,name=seq,proto3" json:"seq,omitempty"`
	Payload              []byte   `protobuf:"bytes,3,opt,name=payload,proto3" json:"payload,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Request_M) Reset()         { *m = Request_M{} }
func (m *Request_M) String() string { return proto.CompactTextString(m) }
func (*Request_M) ProtoMessage()    {}
func (*Request_M) Descriptor() ([]byte, []int) {
	return fileDescriptor_messages_0897251da7b8b1b0, []int{1, 0}
}
func (m *Request_M) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Request_M.Unmarshal(m, b)
}
func (m *Request_M) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Request_M.Marshal(b, m, deterministic)
}
func (dst *Request_M) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Request_M.Merge(dst, src)
}
func (m *Request_M) XXX_Size() int {
	return xxx_messageInfo_Request_M.Size(m)
}
func (m *Request_M) XXX_DiscardUnknown() {
	xxx_messageInfo_Request_M.DiscardUnknown(m)
}

var xxx_messageInfo_Request_M proto.InternalMessageInfo

func (m *Request_M) GetClientId() uint32 {
	if m != nil {
		return m.ClientId
	}
	return 0
}

func (m *Request_M) GetSeq() uint64 {
	if m != nil {
		return m.Seq
	}
	return 0
}

func (m *Request_M) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

type Reply struct {
	Msg                  *Reply_M `protobuf:"bytes,1,opt,name=msg,proto3" json:"msg,omitempty"`
	Signature            []byte   `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Reply) Reset()         { *m = Reply{} }
func (m *Reply) String() string { return proto.CompactTextString(m) }
func (*Reply) ProtoMessage()    {}
func (*Reply) Descriptor() ([]byte, []int) {
	return fileDescriptor_messages_0897251da7b8b1b0, []int{2}
}
func (m *Reply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Reply.Unmarshal(m, b)
}
func (m *Reply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Reply.Marshal(b, m, deterministic)
}
func (dst *Reply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Reply.Merge(dst, src)
}
func (m *Reply) XXX_Size() int {
	return xxx_messageInfo_Reply.Size(m)
}
func (m *Reply) XXX_DiscardUnknown() {
	xxx_messageInfo_Reply.DiscardUnknown(m)
}

var xxx_messageInfo_Reply proto.InternalMessageInfo

func (m *Reply) GetMsg() *Reply_M {
	if m != nil {
		return m.Msg
	}
	return nil
}

func (m *Reply) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

type Reply_M struct {
	ReplicaId            uint32   `protobuf:"varint,1,opt,name=replica_id,json=replicaId,proto3" json:"replica_id,omitempty"`
	ClientId             uint32   `protobuf:"varint,2,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	Seq                  uint64   `protobuf:"varint,3,opt,name=seq,proto3" json:"seq,omitempty"`
	Result               []byte   `protobuf:"bytes,4,opt,name=result,proto3" json:"result,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Reply_M) Reset()         { *m = Reply_M{} }
func (m *Reply_M) String() string { return proto.CompactTextString(m) }
func (*Reply_M) ProtoMessage()    {}
func (*Reply_M) Descriptor() ([]byte, []int) {
	return fileDescriptor_messages_0897251da7b8b1b0, []int{2, 0}
}
func (m *Reply_M) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Reply_M.Unmarshal(m, b)
}
func (m *Reply_M) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Reply_M.Marshal(b, m, deterministic)
}
func (dst *Reply_M) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Reply_M.Merge(dst, src)
}
func (m *Reply_M) XXX_Size() int {
	return xxx_messageInfo_Reply_M.Size(m)
}
func (m *Reply_M) XXX_DiscardUnknown() {
	xxx_messageInfo_Reply_M.DiscardUnknown(m)
}

var xxx_messageInfo_Reply_M proto.InternalMessageInfo

func (m *Reply_M) GetReplicaId() uint32 {
	if m != nil {
		return m.ReplicaId
	}
	return 0
}

func (m *Reply_M) GetClientId() uint32 {
	if m != nil {
		return m.ClientId
	}
	return 0
}

func (m *Reply_M) GetSeq() uint64 {
	if m != nil {
		return m.Seq
	}
	return 0
}

func (m *Reply_M) GetResult() []byte {
	if m != nil {
		return m.Result
	}
	return nil
}

type Prepare struct {
	Msg                  *Prepare_M `protobuf:"bytes,1,opt,name=msg,proto3" json:"msg,omitempty"`
	ReplicaUi            []byte     `protobuf:"bytes,2,opt,name=replica_ui,json=replicaUi,proto3" json:"replica_ui,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *Prepare) Reset()         { *m = Prepare{} }
func (m *Prepare) String() string { return proto.CompactTextString(m) }
func (*Prepare) ProtoMessage()    {}
func (*Prepare) Descriptor() ([]byte, []int) {
	return fileDescriptor_messages_0897251da7b8b1b0, []int{3}
}
func (m *Prepare) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Prepare.Unmarshal(m, b)
}
func (m *Prepare) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Prepare.Marshal(b, m, deterministic)
}
func (dst *Prepare) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Prepare.Merge(dst, src)
}
func (m *Prepare) XXX_Size() int {
	return xxx_messageInfo_Prepare.Size(m)
}
func (m *Prepare) XXX_DiscardUnknown() {
	xxx_messageInfo_Prepare.DiscardUnknown(m)
}

var xxx_messageInfo_Prepare proto.InternalMessageInfo

func (m *Prepare) GetMsg() *Prepare_M {
	if m != nil {
		return m.Msg
	}
	return nil
}

func (m *Prepare) GetReplicaUi() []byte {
	if m != nil {
		return m.ReplicaUi
	}
	return nil
}

type Prepare_M struct {
	View                 uint64   `protobuf:"varint,1,opt,name=view,proto3" json:"view,omitempty"`
	ReplicaId            uint32   `protobuf:"varint,2,opt,name=replica_id,json=replicaId,proto3" json:"replica_id,omitempty"`
	Request              *Request `protobuf:"bytes,3,opt,name=request,proto3" json:"request,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Prepare_M) Reset()         { *m = Prepare_M{} }
func (m *Prepare_M) String() string { return proto.CompactTextString(m) }
func (*Prepare_M) ProtoMessage()    {}
func (*Prepare_M) Descriptor() ([]byte, []int) {
	return fileDescriptor_messages_0897251da7b8b1b0, []int{3, 0}
}
func (m *Prepare_M) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Prepare_M.Unmarshal(m, b)
}
func (m *Prepare_M) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Prepare_M.Marshal(b, m, deterministic)
}
func (dst *Prepare_M) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Prepare_M.Merge(dst, src)
}
func (m *Prepare_M) XXX_Size() int {
	return xxx_messageInfo_Prepare_M.Size(m)
}
func (m *Prepare_M) XXX_DiscardUnknown() {
	xxx_messageInfo_Prepare_M.DiscardUnknown(m)
}

var xxx_messageInfo_Prepare_M proto.InternalMessageInfo

func (m *Prepare_M) GetView() uint64 {
	if m != nil {
		return m.View
	}
	return 0
}

func (m *Prepare_M) GetReplicaId() uint32 {
	if m != nil {
		return m.ReplicaId
	}
	return 0
}

func (m *Prepare_M) GetRequest() *Request {
	if m != nil {
		return m.Request
	}
	return nil
}

type Commit struct {
	Msg                  *Commit_M `protobuf:"bytes,1,opt,name=msg,proto3" json:"msg,omitempty"`
	ReplicaUi            []byte    `protobuf:"bytes,2,opt,name=replica_ui,json=replicaUi,proto3" json:"replica_ui,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *Commit) Reset()         { *m = Commit{} }
func (m *Commit) String() string { return proto.CompactTextString(m) }
func (*Commit) ProtoMessage()    {}
func (*Commit) Descriptor() ([]byte, []int) {
	return fileDescriptor_messages_0897251da7b8b1b0, []int{4}
}
func (m *Commit) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Commit.Unmarshal(m, b)
}
func (m *Commit) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Commit.Marshal(b, m, deterministic)
}
func (dst *Commit) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Commit.Merge(dst, src)
}
func (m *Commit) XXX_Size() int {
	return xxx_messageInfo_Commit.Size(m)
}
func (m *Commit) XXX_DiscardUnknown() {
	xxx_messageInfo_Commit.DiscardUnknown(m)
}

var xxx_messageInfo_Commit proto.InternalMessageInfo

func (m *Commit) GetMsg() *Commit_M {
	if m != nil {
		return m.Msg
	}
	return nil
}

func (m *Commit) GetReplicaUi() []byte {
	if m != nil {
		return m.ReplicaUi
	}
	return nil
}

type Commit_M struct {
	View                 uint64   `protobuf:"varint,1,opt,name=view,proto3" json:"view,omitempty"`
	ReplicaId            uint32   `protobuf:"varint,2,opt,name=replica_id,json=replicaId,proto3" json:"replica_id,omitempty"`
	PrimaryId            uint32   `protobuf:"varint,3,opt,name=primary_id,json=primaryId,proto3" json:"primary_id,omitempty"`
	Request              *Request `protobuf:"bytes,4,opt,name=request,proto3" json:"request,omitempty"`
	PrimaryUi            []byte   `protobuf:"bytes,5,opt,name=primary_ui,json=primaryUi,proto3" json:"primary_ui,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Commit_M) Reset()         { *m = Commit_M{} }
func (m *Commit_M) String() string { return proto.CompactTextString(m) }
func (*Commit_M) ProtoMessage()    {}
func (*Commit_M) Descriptor() ([]byte, []int) {
	return fileDescriptor_messages_0897251da7b8b1b0, []int{4, 0}
}
func (m *Commit_M) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Commit_M.Unmarshal(m, b)
}
func (m *Commit_M) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Commit_M.Marshal(b, m, deterministic)
}
func (dst *Commit_M) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Commit_M.Merge(dst, src)
}
func (m *Commit_M) XXX_Size() int {
	return xxx_messageInfo_Commit_M.Size(m)
}
func (m *Commit_M) XXX_DiscardUnknown() {
	xxx_messageInfo_Commit_M.DiscardUnknown(m)
}

var xxx_messageInfo_Commit_M proto.InternalMessageInfo

func (m *Commit_M) GetView() uint64 {
	if m != nil {
		return m.View
	}
	return 0
}

func (m *Commit_M) GetReplicaId() uint32 {
	if m != nil {
		return m.ReplicaId
	}
	return 0
}

func (m *Commit_M) GetPrimaryId() uint32 {
	if m != nil {
		return m.PrimaryId
	}
	return 0
}

func (m *Commit_M) GetRequest() *Request {
	if m != nil {
		return m.Request
	}
	return nil
}

func (m *Commit_M) GetPrimaryUi() []byte {
	if m != nil {
		return m.PrimaryUi
	}
	return nil
}

func init() {
	proto.RegisterType((*Message)(nil), "messages.Message")
	proto.RegisterType((*Request)(nil), "messages.Request")
	proto.RegisterType((*Request_M)(nil), "messages.Request.M")
	proto.RegisterType((*Reply)(nil), "messages.Reply")
	proto.RegisterType((*Reply_M)(nil), "messages.Reply.M")
	proto.RegisterType((*Prepare)(nil), "messages.Prepare")
	proto.RegisterType((*Prepare_M)(nil), "messages.Prepare.M")
	proto.RegisterType((*Commit)(nil), "messages.Commit")
	proto.RegisterType((*Commit_M)(nil), "messages.Commit.M")
}

func init() { proto.RegisterFile("messages.proto", fileDescriptor_messages_0897251da7b8b1b0) }

var fileDescriptor_messages_0897251da7b8b1b0 = []byte{
	// 420 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x93, 0xdf, 0x8a, 0xd3, 0x40,
	0x14, 0xc6, 0x3b, 0x4d, 0x9a, 0xb4, 0xc7, 0xaa, 0xed, 0x08, 0x12, 0xaa, 0x05, 0x89, 0x8a, 0xa2,
	0xd8, 0x0b, 0x7d, 0x03, 0xbd, 0x69, 0xc1, 0x82, 0x0c, 0xf4, 0x5a, 0x62, 0x32, 0x94, 0x81, 0xa4,
	0x99, 0xce, 0x24, 0x4a, 0xde, 0xc5, 0x9b, 0x7d, 0x87, 0xdd, 0x37, 0xd8, 0x17, 0xda, 0x37, 0x58,
	0xe6, 0x4f, 0x9a, 0x34, 0xbb, 0x65, 0xcb, 0xde, 0xe5, 0x9c, 0xef, 0x9b, 0xc3, 0xef, 0x3b, 0x3d,
	0x85, 0x67, 0x19, 0x95, 0x32, 0xda, 0x52, 0xb9, 0xe0, 0x22, 0x2f, 0x72, 0x3c, 0xac, 0xeb, 0xf0,
	0x1a, 0x81, 0xbf, 0x36, 0x05, 0xfe, 0x02, 0xbe, 0xa0, 0xfb, 0x92, 0xca, 0x22, 0x40, 0x6f, 0xd0,
	0xc7, 0x27, 0x5f, 0xa7, 0x8b, 0xc3, 0x3b, 0x62, 0x84, 0x65, 0x8f, 0xd4, 0x1e, 0xfc, 0x01, 0x06,
	0x82, 0xf2, 0xb4, 0x0a, 0xfa, 0xda, 0xfc, 0xbc, 0x6d, 0xe6, 0x69, 0xb5, 0xec, 0x11, 0xa3, 0xab,
	0xb9, 0x5c, 0x50, 0x1e, 0x09, 0x1a, 0x38, 0xdd, 0xb9, 0xbf, 0x8c, 0xa0, 0xe6, 0x5a, 0x0f, 0xfe,
	0x04, 0x5e, 0x9c, 0x67, 0x19, 0x2b, 0x02, 0x57, 0xbb, 0x27, 0x8d, 0xfb, 0x87, 0xee, 0x2f, 0x7b,
	0xc4, 0x3a, 0xbe, 0x7b, 0xe0, 0x16, 0x15, 0xa7, 0xe1, 0x7f, 0x04, 0xbe, 0x45, 0xc4, 0xef, 0xc1,
	0xc9, 0xe4, 0xd6, 0x46, 0x78, 0x71, 0x27, 0xc2, 0x62, 0x4d, 0x94, 0x8e, 0x5f, 0xc3, 0x48, 0xb2,
	0xed, 0x2e, 0x2a, 0x4a, 0x41, 0x75, 0x84, 0x31, 0x69, 0x1a, 0xb3, 0x9f, 0x80, 0xd6, 0xf8, 0x15,
	0x8c, 0xe2, 0x94, 0xd1, 0x5d, 0xf1, 0x9b, 0x25, 0x7a, 0xde, 0x53, 0x32, 0x34, 0x8d, 0x55, 0x82,
	0x27, 0xe0, 0x48, 0xba, 0xd7, 0x2f, 0x5d, 0xa2, 0x3e, 0x71, 0x00, 0x3e, 0x8f, 0xaa, 0x34, 0x8f,
	0x12, 0x9d, 0x73, 0x4c, 0xea, 0x32, 0xbc, 0x42, 0x30, 0xd0, 0x4b, 0xc1, 0x6f, 0xdb, 0x70, 0xd3,
	0xce, 0xca, 0xce, 0x43, 0x63, 0x0a, 0x6d, 0x0e, 0xa0, 0x96, 0xcb, 0xe2, 0xa8, 0x61, 0x1b, 0xd9,
	0xce, 0x2a, 0x39, 0x26, 0xef, 0xdf, 0x4f, 0xee, 0x34, 0xe4, 0x2f, 0xc1, 0x13, 0x54, 0x96, 0xa9,
	0x59, 0xf9, 0x98, 0xd8, 0x2a, 0xbc, 0x44, 0xe0, 0xdb, 0x5f, 0xe8, 0xe4, 0x5a, 0xad, 0x5e, 0xb3,
	0xb7, 0xc0, 0x4a, 0x56, 0xc3, 0xdb, 0xce, 0x86, 0xcd, 0x62, 0x05, 0x8f, 0xc1, 0xfd, 0xcb, 0xe8,
	0x3f, 0x3d, 0xcb, 0x25, 0xfa, 0xbb, 0x13, 0xa8, 0xdf, 0x0d, 0xf4, 0xb9, 0xb9, 0x4d, 0xe7, 0xc4,
	0x6d, 0x1e, 0x2e, 0x33, 0xbc, 0x41, 0xe0, 0x99, 0x53, 0xc1, 0xef, 0xda, 0xd4, 0xb8, 0x7b, 0x49,
	0x67, 0x42, 0x5f, 0xa0, 0x47, 0x52, 0xcf, 0x01, 0xb8, 0x60, 0x59, 0x24, 0x2a, 0x25, 0x3b, 0x46,
	0xb6, 0x9d, 0xe3, 0x50, 0xee, 0x43, 0xa1, 0xda, 0xb3, 0x4a, 0x16, 0x0c, 0x0c, 0xa3, 0xed, 0x6c,
	0xd8, 0x1f, 0x4f, 0xff, 0xb3, 0xbf, 0xdd, 0x06, 0x00, 0x00, 0xff, 0xff, 0xde, 0x72, 0x28, 0x0a,
	0xeb, 0x03, 0x00, 0x00,
}
