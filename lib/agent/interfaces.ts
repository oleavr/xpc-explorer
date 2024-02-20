export interface AgentApi {
    init(): Promise<void>;
    symbolicate(addresses: string[]): Promise<AddressInfo[]>;
    disassemble(blocks: BasicBlockDescriptor[]): Promise<string[]>
    trimCloakedBlocks(blocks: BasicBlockDescriptor[]): Promise<TrimLimits>;
}

export interface BasicBlockDescriptor {
    start: string;
    end: string;
}

export interface TrimLimits {
    fromIndex: number;
    toIndex: number;
}

export interface AddressInfo {
    moduleOffset: string;
    name: string | null;
}

