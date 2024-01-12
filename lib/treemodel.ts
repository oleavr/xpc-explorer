import { ItemDataRole, QTreeWidget, QTreeWidgetItem, QVariant } from "@nodegui/nodegui";
import { BasicBlockDescriptor } from "./agent/interfaces";
import { QVariantType } from "@nodegui/nodegui/dist/lib/QtCore/QVariant";

const leakedJunk: any[] = [];

export class TreeModel {
    #root: Node | null = null;

    constructor(public id: number) {
    }

    add(trace: Buffer) {
        const blocks = parseTrace(trace);
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
            for (let rootNode of collapsedRoot.children) {
                const rootItem = this.#makeCollapsedItem(rootNode, widget);
                this.#recurseRenderCollapsed(rootItem, rootNode);
            }
        } else {
            for (let rootNode of this.#root.children) {
                const rootItem = this.#makeItem(rootNode, widget);
                this.#recurseRender(rootItem, rootNode);
            }
        }
    }

    #makeItem({ bb }: Node, parent: QTreeWidget | QTreeWidgetItem) {
        const item = new QTreeWidgetItem(parent as QTreeWidget);
        leakedJunk.push(item);
        item.setText(0, `${bb.start} - ${bb.end}`);
        const data = {
            id: this.id,
            bbs: [ bb ]
        };
        item.setData(0, ItemDataRole.UserRole, JSON.stringify(data));
        return item;
    }

    #makeCollapsedItem({ bbs }: CollapsedNode, parent: QTreeWidget | QTreeWidgetItem) {
        const item = new QTreeWidgetItem(parent as QTreeWidget);
        leakedJunk.push(item);
        item.setText(0, (bbs.length !== 0) ? `${bbs[0].start} ... ${bbs[bbs.length - 1].end}` : "(empty)");
        const data = {
            id: this.id,
            bbs
        };
        item.setData(0, ItemDataRole.UserRole, JSON.stringify(data));
        return item;
    }

    #recurseRender(rootItem: QTreeWidgetItem, rootNode: Node) {
        for (const node of rootNode.children) {
            const item = this.#makeItem(node, rootItem);
            this.#recurseRender(item, node);
        }
    }

    #recurseRenderCollapsed(rootItem: QTreeWidgetItem, rootNode: CollapsedNode) {
        for (const node of rootNode.children) {
            const item = this.#makeCollapsedItem(node, rootItem);
            this.#recurseRenderCollapsed(item, node);
        }
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