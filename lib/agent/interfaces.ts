export interface AgentApi {
    init(): Promise<void>;
    symbolicate(addresses: string[]): Promise<string[]>;
    disassemble(blocks: BasicBlockDescriptor[]): Promise<string[]>
}

export interface BasicBlockDescriptor {
    start: string;
    end: string;
}
