from scapy.all import ShortField, IntField, LongField, BitField,             \
                        FieldListField, FieldLenField, Packet,               \
                        XIntField, ByteField, StrFixedLenField,              \
                        DestIPField

class IPFIX_Header(Packet):
    name = "IPFIX Postcard"
    fields_desc=[
        ShortField("IPFIX Version",0),
        ShortField("IPFIX Length",0),
        IntField("Export Time",0),
        IntField("Sequence Number",0),
        DestIPField("Domain",b"0.0.0.0")
        ]

class IPFIX_Set(Packet):
    name = "IPFIX Set"
    fields_desc=[
        ShortField("Set ID",0),
        ShortField("Set Length",0)
    ]

class IPFIX_Record(Packet):
    name = "INT Postcard"
    fields_desc = [
        XIntField("Flow ID",0),
        ByteField("TTL",0),
        StrFixedLenField("Ingress Timestamp", b"", length=6),
        StrFixedLenField("Egress Timestamp", b"", length=6),
        IntField("Enq QDepth",0),
        IntField("Deq QDepth",0),
        ShortField("Ingress Interface",0),
        ShortField("Egress Interface",0),
        XIntField("SW ID",0),
        IntField("Export Time",0),
        IntField("Sequence Number",0)
    ]
