import { ItemDataRole, QTreeWidget, QTreeWidgetItem } from "@nodegui/nodegui";
import { AgentApi, BasicBlockDescriptor } from "./agent/interfaces.js";
import { describeAddressInfo } from "./info.js";

const leakedJunk: any[] = [];

export class TreeModel {
    #id: number;
    #root: Node | null = null;

    #agent: AgentApi;

    constructor(id: number, agent: AgentApi) {
        this.#id = id;
        this.#agent = agent;
    }

    async add(trace: Buffer) {
        const blocks = await this.#trimCloakedBlocks(parseTrace(trace));
        let cursor = this.#root;
        for (const bb of blocks) {
            if (bb === undefined) {
                console.log("PARSE ERROR");
            }
            let parent = cursor;
            cursor = this.#childMatching(cursor, bb);
            if (cursor === null) {
                cursor = this.#addChild(parent, { bb, children: [] });
            }
        }
    }

    render(widget: QTreeWidget, collapsed: boolean) {
        if (this.#root === null) {
            return;
        }
        widget.clear();

        if (collapsed) {
            const collapsedRoot = this.#collapse();
            this.#recurseRenderCollapsed(widget, collapsedRoot);
        } else {
            this.#recurseRender(widget, this.#root);
        }
    }

    #recurseRender(container: QTreeWidget | QTreeWidgetItem, node: Node) {
        const parent = this.#makeItem([ node.bb ], container);
        for (const child of node.children) {
            this.#recurseRender(parent, child);
        }
    }

    #recurseRenderCollapsed(container: QTreeWidget | QTreeWidgetItem, node: CollapsedNode) {
        const parent = this.#makeItem(node.bbs, container);
        for (const child of node.children) {
            this.#recurseRenderCollapsed(parent, child);
        }
    }

    #makeItem(bbs: BasicBlockDescriptor[], parent: QTreeWidget | QTreeWidgetItem) {
        const item = new QTreeWidgetItem(parent as QTreeWidget);
        leakedJunk.push(item);

        if (bbs.length !== 0) {
            const startAddress = bbs[0].start;
            const endAddress = bbs[bbs.length - 1].end;
            item.setText(0, `${startAddress} ... ${endAddress}`);
            this.#decorateItem(item, startAddress, endAddress);
        } else {
            item.setText(0, "Empty");
        }

        const data = {
            id: this.#id,
            bbs
        };
        item.setData(0, ItemDataRole.UserRole, JSON.stringify(data));
        item.setExpanded(true);

        return item;
    }

    async #decorateItem(item: QTreeWidgetItem, startAddress: string, endAddress: string) {
        try {
            const [ startInfo, endInfo ] = await this.#agent.symbolicate([ startAddress, endAddress ]);
            item.setText(0, `${describeAddressInfo(startInfo)} ... ${describeAddressInfo(endInfo)}`);
        } catch (e) {
            console.error(e);
        }
    }

    async #trimCloakedBlocks(bbs: BasicBlockDescriptor[]): Promise<BasicBlockDescriptor[]> {
        const CHUNK_SIZE = 100;

        if (bbs.length < CHUNK_SIZE) {
            const limits = await this.#agent.trimCloakedBlocks(bbs);
            return bbs.slice(limits.fromIndex, limits.toIndex + 1);
        }

        let fromIndex = bbs.length;
        for (let i = 0; i < bbs.length; i += CHUNK_SIZE) {
            const chunk = bbs.slice(i, i + CHUNK_SIZE);
            const chunkLimits = await this.#agent.trimCloakedBlocks(chunk);
            if (chunkLimits.fromIndex < chunk.length) {
                fromIndex = chunkLimits.fromIndex + i;
                break;
            }
        }

        let toIndex = -1;
        for (let i = bbs.length - CHUNK_SIZE; i >= 0; i -= Math.min(CHUNK_SIZE, i)) {
            const chunk = bbs.slice(i, i + CHUNK_SIZE);
            const chunkLimits = await this.#agent.trimCloakedBlocks(chunk);
            if (chunkLimits.toIndex >= 0) {
                toIndex = chunkLimits.toIndex + i;
                break;
            }
        }

        return bbs.slice(fromIndex, toIndex + 1);
    }

    toString(collapsed: boolean): string {
        if (this.#root === null) {
            return "";
        }

        const lines: string[] = [];

        if (collapsed) {
            const collapsedRoot = this.#collapse();

            this.#visit(collapsedRoot, 0, (node, depth) => {
                if (node.bbs.length === 0) {
                    lines.push(`${spaces(depth)}+ BUG`);
                    return;
                }
                lines.push(`${spaces(depth)}+ ${node.bbs[0].start} ... ${node.bbs[node.bbs.length - 1].end}`);
            });
        } else {
            this.#visit(this.#root, 0, (node, depth) => {
                lines.push(`${spaces(depth)}+ ${node.bb.start} - ${node.bb.end}`);
            });    
        }

        return lines.join("\n");

        function spaces(length: number): string {
            const result: string[] = [];
            for (let i = 0; i !== length; i++) {
                result.push(" ");
            }
            return result.join("");
        }
    }

    #addChild(parent: Node | null, child: Node): Node {
        if (parent === null) {
            if (this.#root !== null) {
                throw new Error("Tree has already a root");
            }
            this.#root = child;
        } else {
            parent.children.push(child);
        }

        return child;
    }

    #childMatching(parent: Node | null, matching: BasicBlockDescriptor): Node | null {
        if (parent === null) {
            return null;
        }

        for (const child of parent.children) {
            if (areBlocksEqual(child.bb, matching)) {
                return child;
            }
        }

        return null;
    }

    #visit<T extends Visitable<T>>(root: T, depth: number, callback: (node: T, depth: number) => void) {
        callback(root, depth);

        for (const child of root.children) {
            this.#visit(child, depth + 1, callback);
        }
    }

    #collapse(): CollapsedNode {
        const collapsed = {
            bbs: [],
            children: []
        };

        if (this.#root !== null) {
            this.#collapseVisit(this.#root, collapsed);
        }

        return collapsed;
    }

    #collapseVisit(root: Node, collapsed: CollapsedNode) {
        collapsed.bbs.push(root.bb);

        let cursor = root;
        while (cursor.children.length === 1) {
            const onlyChild = cursor.children[0];
            collapsed.bbs.push(onlyChild.bb);
            cursor = onlyChild;
        }

        if (cursor.children.length > 1) {
            for (const child of cursor.children) {
                const collapsedChild = {
                    bbs: [],
                    children: []
                };
                collapsed.children.push(collapsedChild);
                this.#collapseVisit(child, collapsedChild);
            }
        }
    }
}

export interface TreeItemData {
    id: number;
    bbs: BasicBlockDescriptor[];
}

function parseTrace(trace: Buffer): BasicBlockDescriptor[] {
    const result: BasicBlockDescriptor[] = [];

    const eventSize = 32;
    const size = trace.length;

    for (let offset = 0; offset < size; offset += eventSize) {
        const type = trace.readUInt32LE(offset);
        if (type !== 8) {
            continue;
        }

        const start = `0x${trace.readBigUInt64LE(offset + 8).toString(16)}`;
        const end = `0x${trace.readBigUInt64LE(offset + 16).toString(16)}`;

        result.push({ start, end });
    }

    return result;
}

function areBlocksEqual(a: BasicBlockDescriptor, b: BasicBlockDescriptor): boolean {
    return a.start === b.start;
}

interface Visitable<T> {
    children: T[];
}

interface Node extends Visitable<Node> {
    bb: BasicBlockDescriptor;
}

interface CollapsedNode extends Visitable<CollapsedNode> {
    bbs: BasicBlockDescriptor[];
}