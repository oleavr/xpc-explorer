export interface AgentApi {
    init(): Promise<void>;
    symbolicate(addresses: string[]): Promise<string[]>;
}
