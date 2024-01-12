import { QTreeWidget } from "@nodegui/nodegui";
import { BasicBlockDescriptor } from "./agent/interfaces";

export class TreeModel {
    #root: Node | null = null;

    constructor() {
    }

    add(trace: Buffer) {
        const blocks = parseTrace(trace);
        let cursor = this.#root;
        for (const bb of blocks) {
            let parent = cursor;
            cursor = this.#childMatching(cursor, bb);
            if (cursor === null) {
                cursor = this.#addChild(parent, { bb: bb, children: [] });
            }
        }
    }

    render(widget: QTreeWidget, collapse: boolean) {
        widget.clear();
    }

    toString(collapsed: boolean): string {
        if (this.#root === null) {
            return "";
        }

        const lines: string[] = [];

        if (collapsed) {
            const collapsedRoot = this.#collapse();

            this.#visit(collapsedRoot, 0, (node, depth) => {
                if (node) {
    
                }
                lines.push(`${spaces(depth)}+ ${node.bbs[0].start} ... ${node.bbs[node.bbs.length - 1].end}`);
                return true;
            });
        } else {
            this.#visit(this.#root, 0, (node, depth) => {
                if (node) {
    
                }
                lines.push(`${spaces(depth)}+ ${node.bb.start} - ${node.bb.end}`);
                return true;
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