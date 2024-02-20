import { AddressInfo } from "./agent/interfaces";

export function describeAddressInfo(info: AddressInfo): string {
    const { name, moduleOffset } = info;
    if (name !== null) {
        return `${moduleOffset} ${name}`;
    }
    return moduleOffset;
}
