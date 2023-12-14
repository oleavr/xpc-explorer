import { AgentApi } from "./interfaces.js";

const LIBSYSTEM_KERNEL = "/usr/lib/system/libsystem_kernel.dylib";
const LIBXPC = "/usr/lib/system/libxpc.dylib";

const nfOpts: NativeFunctionOptions = { exceptions: "propagate" };

const xpcArrayGetCount = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_array_get_count"), "size_t", ["pointer"], nfOpts);
const xpcArrayGetValue = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_array_get_value"), "pointer", ["pointer", "size_t"], nfOpts);
const xpcBoolGetValue = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_bool_get_value"), "bool", ["pointer"], nfOpts);
const xpcConnectionGetPid = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_connection_get_pid"), "uint", ["pointer"]);
const xpcDataGetBytesPtr = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_data_get_bytes_ptr"), "pointer", ["pointer"], nfOpts);
const xpcDataGetLength = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_data_get_length"), "size_t", ["pointer"], nfOpts);
const xpcDictionaryApply = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_dictionary_apply"), "bool", ["pointer", "pointer"], nfOpts);
const xpcDictionaryGetString = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_dictionary_get_string"), "pointer", ["pointer", "pointer"], nfOpts);
const xpcFdDup = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_fd_dup"), "int", ["pointer"], nfOpts);
const xpcGetType = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_get_type"), "pointer", ["pointer"], nfOpts);
const xpcInt64GetValue = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_int64_get_value"), "int64", ["pointer"], nfOpts);
const xpcStringGetStringPtr = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_string_get_string_ptr"), "pointer", ["pointer"], nfOpts);
const xpcTypeGetName = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_type_get_name"), "pointer", ["pointer"], nfOpts);
const xpcUInt64GetValue = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_uint64_get_value"), "uint64", ["pointer"], nfOpts);
const xpcUuidGetBytes = new NativeFunction(Module.getExportByName(LIBXPC, "xpc_uuid_get_bytes"), "pointer", ["pointer"], nfOpts);

const close = new NativeFunction(Module.getExportByName(LIBSYSTEM_KERNEL, "close"), "int", ["int"], nfOpts);

const XPC_ERROR_KEY_DESCRIPTION = Module.getExportByName(LIBXPC, "_xpc_error_key_description").readPointer();

type XpcObjectParser = (obj: NativePointer) => XpcValue;

type XpcValue =
    | boolean
    | number
    | XpcData
    | string
    | XpcFd
    | XpcArray
    | XpcDictionary
    | XpcError
    | XpcConnection
    | XpcEndpoint
    ;
type XpcData = [ type: "data", hexified: string ];
type XpcFd = [ type: "fd", details: XpcFdDetails ];
type XpcArray = XpcValue[];
type XpcDictionary = { [key: string]: XpcValue };
type XpcError = [ type: "error", description: string ];
type XpcConnection = [ type: "connection", details: XpcConnectionDetails ];
type XpcEndpoint = [ type: "endpoint", details: XpcEndpointDetails ];

interface XpcFdDetails {
    socket?: XpcSocketDetails;
}

interface XpcSocketDetails {
    type: SocketType;
    localAddress: SocketEndpointAddress | null;
    remoteAddress: SocketEndpointAddress | null;
}

interface XpcConnectionDetails {
    handle: NativePointer;
    pid: number;
}

interface XpcEndpointDetails {
    port: number;
}

const xpcParsers = new Map<string, XpcObjectParser>();

registerXpcParsers();

class Agent implements AgentApi {
    public async init(): Promise<void> {
        console.log(`Hello World from PID: ${Process.id}`);
        console.warn("Example warning");
        console.error("Example error");
    }
}

Interceptor.attach(DebugSymbol.getFunctionByName("_xpc_connection_call_event_handler"), function (args) {
    const connection = args[0];
    const event = parseXpcObject(args[1]);
    console.log(`<<< [${connection}] ${JSON.stringify(event)}`);
});

[
    "xpc_connection_send_message",
    "xpc_connection_send_message_with_reply",
    "xpc_connection_send_message_with_reply_sync",
].forEach(name => {
    Interceptor.attach(Module.getExportByName(LIBXPC, name), function (args) {
        const connection = args[0];
        const message = parseXpcObject(args[1]);
        console.log(`>>> [${connection}] ${JSON.stringify(message)}`);
    });
});

function parseXpcObject(obj: NativePointer): XpcValue {
    const type = xpcGetType(obj);
    const parse = xpcParsers.get(type.toString());
    if (parse === undefined) {
        return `<TODO: ${xpcTypeGetName(type).readUtf8String()}>`;
    }
    return parse(obj);
}

function registerXpcParsers() {
    registerXpcParser("bool", parseXpcBool);
    registerXpcParser("int64", parseXpcInt64);
    registerXpcParser("uint64", parseXpcUint64);
    registerXpcParser("data", parseXpcData);
    registerXpcParser("string", parseXpcString);
    registerXpcParser("uuid", parseXpcUuid);
    registerXpcParser("fd", parseXpcFd);
    registerXpcParser("array", parseXpcArray);
    registerXpcParser("dictionary", parseXpcDictionary);
    registerXpcParser("error", parseXpcError);
    registerXpcParser("connection", parseXpcConnection);
    registerXpcParser("endpoint", parseXpcEndpoint);
}

function registerXpcParser(id: string, parser: XpcObjectParser) {
    xpcParsers.set(Module.getExportByName(LIBXPC, "_xpc_type_" + id).toString(), parser);
}

function parseXpcBool(obj: NativePointer): boolean {
    return (xpcBoolGetValue(obj) !== 0) ? true : false;
}

function parseXpcInt64(obj: NativePointer): number {
    return xpcInt64GetValue(obj).valueOf();
}

function parseXpcUint64(obj: NativePointer): number {
    return xpcUInt64GetValue(obj).valueOf();
}

function parseXpcData(obj: NativePointer): XpcData {
    return ["data", hexify(xpcDataGetBytesPtr(obj).readByteArray(xpcDataGetLength(obj).valueOf())!)];
}

function parseXpcString(obj: NativePointer): string {
    return xpcStringGetStringPtr(obj).readUtf8String()!;
}

function parseXpcUuid(obj: NativePointer): string {
    const result: string[] = [];
    const data = new Uint8Array(ArrayBuffer.wrap(xpcUuidGetBytes(obj), 16));
    for (let i = 0; i !== 16; i++) {
        let v = data[i].toString(16).toUpperCase();
        if (v.length === 1)
            v = "0" + v;
        result.push(v);
        switch (i) {
            case 3:
            case 5:
            case 7:
            case 9:
                result.push("-");
        }
    }
    return result.join("");
}

function parseXpcFd(obj: NativePointer): XpcFd {
    const fd = xpcFdDup(obj);
    try {
        let socket: XpcSocketDetails | undefined;

        const type = Socket.type(fd);
        if (type !== null) {
            socket = {
                type,
                localAddress: Socket.localAddress(fd),
                remoteAddress: Socket.peerAddress(fd),
            };
        }

        return ["fd", { socket }];
    } finally {
        close(fd);
    }
}

function parseXpcArray(obj: NativePointer): XpcValue[] {
    const result: any[] = [];
    const n = xpcArrayGetCount(obj).valueOf();
    for (let i = 0; i !== n; i++) {
        result.push(parseXpcObject(xpcArrayGetValue(obj, i)));
    }
    return result;
}

function parseXpcDictionary(obj: NativePointer): XpcDictionary {
    const result: { [key: string]: any } = {};
    const collectEntries = new ObjC.Block({
        retType: "bool",
        argTypes: ["pointer", "pointer"],
        implementation(rawKey: NativePointer, value: NativePointer) {
            const key = rawKey.readUtf8String()!;
            result[key] = parseXpcObject(value);
            return true;
        }
    });
    xpcDictionaryApply(obj, collectEntries);
    return result;
}

function parseXpcError(obj: NativePointer): XpcError {
    return ["error", xpcDictionaryGetString(obj, XPC_ERROR_KEY_DESCRIPTION).readUtf8String()!];
}

function parseXpcConnection(obj: NativePointer): XpcConnection {
    return ["connection", {
        handle: obj,
        pid: xpcConnectionGetPid(obj)
    }];
}

function parseXpcEndpoint(obj: NativePointer): XpcEndpoint {
    return ["endpoint", { port: obj.add(0x18).readU32() }];
}

function hexify(data: ArrayBuffer): string {
    return hexdump(data, { header: false })
        .split("\n")
        .map(line => line.substring(10, 57).trimEnd())
        .join(" ");
}

const agent = new Agent();
rpc.exports = Object.getPrototypeOf(agent);
