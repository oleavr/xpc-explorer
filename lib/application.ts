import { AgentApi, BasicBlockDescriptor } from "./agent/interfaces.js";
import {
    Config,
    TargetDevice,
    TargetProcess,
    TargetProcessAllByName,
    TargetProcessById,
} from "./config.js";
import { Operation, AsyncOperation } from "./operation.js";

import {
    ItemDataRole,
    QBoxLayout,
    QGroupBox,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QSplitter,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
} from "@nodegui/nodegui";
import { EventEmitter } from "events";
import * as frida from "frida";
import {
    Cancellable,
    Child,
    Device,
    LogLevel,
    Message,
    MessageType,
    Process,
    Script,
    ScriptRuntime,
    Session,
    SessionDetachReason,
    SpawnAddedHandler,
} from "frida";
import * as fs from "fs";
import { promisify } from "util";
import { TreeModel, TreeItemData } from "./treemodel.js";

const readFile = promisify(fs.readFile);

const rootStyleSheet = `
#rootGroup {
    padding: 5px;
}
`;

export class Application {
    #config: Config;
    #delegate: Delegate;

    #controllers: DeviceController[] = [];
    #cancellable = new Cancellable();

    #scheduler: OperationScheduler;

    #window = new QMainWindow();
    #handlerView = new QListWidget();
    #eventView = new QListWidget();
    #eventDetailsView = new QTextEdit();
    #tracesView = new QTreeWidget();
    #disassView = new QTextEdit();

    #handlers: XpcHandler[] = [];

    constructor(config: Config, delegate: Delegate) {
        this.#config = config;
        this.#delegate = delegate;

        this.#scheduler = new OperationScheduler("application", delegate);

        const rootGroup = new QGroupBox();
        const rootLayout = new QBoxLayout(2);
        rootGroup.setObjectName("rootGroup");
        rootGroup.setLayout(rootLayout);

        const topSplitter = new QSplitter();
        rootLayout.addWidget(topSplitter);

        const handlerGroup = new QGroupBox();
        handlerGroup.setTitle("Handlers");
        topSplitter.addWidget(handlerGroup);
        const handlerLayout = new QBoxLayout(2);
        handlerLayout.addWidget(this.#handlerView);
        handlerGroup.setLayout(handlerLayout);
        this.#handlerView.addEventListener("currentRowChanged", this.#onHandlerViewCurrentRowChanged);

        const eventGroup = new QGroupBox();
        eventGroup.setTitle("Events");
        topSplitter.addWidget(eventGroup);
        const eventLayout = new QBoxLayout(2);
        eventLayout.addWidget(this.#eventView);
        eventLayout.addWidget(this.#eventDetailsView);
        eventGroup.setLayout(eventLayout);
        this.#eventView.setSelectionMode(2);
        this.#eventView.addEventListener("itemSelectionChanged", this.#onEventViewItemSelectionChanged);

        const tracesGroup = new QGroupBox();
        tracesGroup.setTitle("Executed Traces on the Handler");
        topSplitter.addWidget(tracesGroup);
        this.#tracesView.addEventListener("currentItemChanged", this.#onTracesViewCurrentRowChanged);
        const dataLayout = new QBoxLayout(2);
        dataLayout.addWidget(this.#tracesView);
        tracesGroup.setLayout(dataLayout);

        const disassGroup = new QGroupBox();
        disassGroup.setTitle("Disassembly");
        const disassLayout = new QBoxLayout(0);
        disassLayout.addWidget(this.#disassView);
        disassGroup.setLayout(disassLayout);
        this.#disassView.setReadOnly(true);
        this.#disassView.setFontFamily("Courier");
        rootLayout.addWidget(disassGroup);

        this.#window.setWindowTitle("xpc-explorer");
        this.#window.setStyleSheet(rootStyleSheet);
        this.#window.setCentralWidget(rootGroup);
        this.#window.show();
    }

    public async dispose(): Promise<void> {
        for (const controller of this.#controllers) {
            await controller.dispose();
        }

        this.#cancellable.cancel();
    }

    public async run(): Promise<void> {
        const controllerByDeviceId = new Map<string, DeviceController>();

        try {
            console.log(JSON.stringify(this.#config.targets));
            for (const target of this.#config.targets) {
                const device = await this.#getDevice(target.device);
                const { id: deviceId } = device;

                let controller = controllerByDeviceId.get(deviceId);
                if (controller === undefined) {
                    controller = new DeviceController(device, this.#delegate, this, this.#scheduler, this.#cancellable);
                    controllerByDeviceId.set(deviceId, controller);
                    this.#controllers.push(controller);
                }

                await controller.add(target.processes);
            }

            await Promise.all(this.#controllers.map(c => c.join()));
        } finally {
            this.dispose();
        }
    }

    async #getDevice(targetDevice: TargetDevice): Promise<Device> {
        return this.#scheduler.perform("Getting device", async (): Promise<Device> => {
            let device: Device;

            switch (targetDevice.kind) {
                case "local":
                    device = await frida.getLocalDevice(this.#cancellable);
                    break;
                case "usb":
                    device = await frida.getUsbDevice(undefined, this.#cancellable);
                    break;
                case "remote":
                    device = await frida.getRemoteDevice(this.#cancellable);
                    break;
                case "by-host":
                    device = await frida.getDeviceManager().addRemoteDevice(targetDevice.host, undefined, this.#cancellable);
                    break;
                case "by-id":
                    device = await frida.getDevice(targetDevice.id, undefined, this.#cancellable);
                    break;
                default:
                    throw new Error("Invalid target device");
            }

            return device;
        });
    }

    async onTrace({ handler: handlerId, event }: TraceDetails, trace: Buffer, agent: AgentApi) {
        let handler: XpcHandler;
        let handlerSeenBefore = true;
        let index = this.#handlers.findIndex(h => h.id === handlerId);
        if (index !== -1) {
            handler = this.#handlers[index];
        } else {
            handlerSeenBefore = false;

            handler = {
                id: handlerId,
                name: null,
                invocations: [],
                agent,
            };
            index = this.#handlers.length;
            this.#handlers.push(handler);
        }

        const invocation: XpcHandlerInvocation = {
            event,
            trace,
        };
        handler.invocations.push(invocation);

        if (this.#handlerView.currentRow() === index) {
            this.#addInvocationToUI(invocation);
        }

        if (!handlerSeenBefore) {
            const item = new QListWidgetItem();
            item.setText(handlerId);
            this.#handlerView.addItem(item);

            const [ name ] = await agent.symbolicate([ handlerId ]);
            handler.name = name;
            item.setText(name);
        }
    }

    #onHandlerViewCurrentRowChanged = (currentRow: number) => {
        const handler = this.#handlers[currentRow];
        this.#eventView.clear();
        for (const invocation of handler.invocations) {
            this.#addInvocationToUI(invocation);
        }
        this.#eventView.setCurrentRow(-1);
    };

    #onEventViewItemSelectionChanged = async () => {
        this.#tracesView.clear();

        const handlerIndex = this.#handlerView.currentRow();
        const handler = this.#handlers[handlerIndex];
        const rowItems = this.#eventView.selectedItems().map((item) => this.#eventView.row(item));
        const tree = new TreeModel(handlerIndex);
        for (let currentRow of rowItems) {
            const invocation = handler.invocations[currentRow];
            if (invocation === undefined) {
                return;
            }

            const { trace, event } = invocation;
            this.#eventDetailsView.setText(JSON.stringify(event, null, 2));
            tree.add(trace);
        }
        tree.render(this.#tracesView, true);
        //console.log(tree.toString(true));
    };

    #onTracesViewCurrentRowChanged = async (currentItem: QTreeWidgetItem | null) => {
        if (currentItem === null) {
            this.#disassView.clear();
            return;
        }

        const data: TreeItemData = JSON.parse(currentItem.data(0, ItemDataRole.UserRole).toString());
        const handler = this.#handlers[data.id];

        const lines = [];
        for (const disassembly of await handler.agent.disassemble(data.bbs.slice(0, 10))) {
            if (lines.length !== 0) {
                lines.push("\n------------------------");
            }
            lines.push(disassembly);
        }
        this.#disassView.setText(lines.join("\n"));
    }

    #addInvocationToUI(invocation: XpcHandlerInvocation) {
        const item = new QListWidgetItem();
        item.setText(JSON.stringify(invocation.event));
        this.#eventView.addItem(item);
    }
}

interface XpcHandler {
    id: string;
    name: string | null;
    invocations: XpcHandlerInvocation[];
    agent: AgentApi;
}

interface XpcHandlerInvocation {
    event: any;
    trace: Buffer;
}

interface TraceDetails {
    handler: string;
    event: any;
    pid: number;
}

class DeviceController {
    #delegate: Delegate;
    #application: Application;
    #scheduler: OperationScheduler;
    #cancellable: Cancellable;

    #done: Promise<void>;
    #onSuccess: () => void = () => {};
    #onFailure: (error: Error) => void = () => {};
    #enlistTask: Promise<void> | null = null;

    #processes: Map<number, Process> = new Map<number, Process>()
    #agents: Map<number, Agent> = new Map<number, Agent>();

    #onSpawnGatingDisabled: (error: Error) => void = () => {};

    constructor(public device: Device, delegate: Delegate, application: Application, scheduler: OperationScheduler,
            cancellable: Cancellable) {
        this.#delegate = delegate;
        this.#application = application;
        this.#scheduler = scheduler;
        this.#cancellable = cancellable;

        this.#done = new Promise((resolve, reject) => {
            this.#onSuccess = resolve;
            this.#onFailure = reject;
        });

        device.childAdded.connect(this.#onChildAdded);
    }

    async dispose() {
        await Promise.all(Array.from(this.#agents.values()).map(a => a.dispose()));

        this.device.childAdded.disconnect(this.#onChildAdded);
        await this.#disableSpawnGating();
    }

    async add(targetProcesses: TargetProcess[]) {
        const { device } = this;
        const processes = this.#processes;

        const allByNameTargets: TargetProcessAllByName[] = [];

        for (const targetProcess of targetProcesses) {
            for (const process of await this.#getProcesses(targetProcess)) {
                const { pid } = process;
                if (!processes.has(pid)) {
                    processes.set(pid, process);

                    const agent = await this.#instrument(process.pid, process.name);

                    if (targetProcess.kind === "spawn" || targetProcess.kind === "by-gating") {
                        await agent.scheduler.perform("Resuming", (): Promise<void> => {
                            return device.resume(process.pid);
                        });
                    }

                    if (targetProcess.kind === "all-by-name") {
                        allByNameTargets.push(targetProcess);
                    }
                }
            }
        }

        if (allByNameTargets.length !== 0) {
            this.#enlistTask = this.#enlistNewProcesses(allByNameTargets);
        }
    }

    join(): Promise<void> {
        return this.#done;
    }

    async #instrument(pid: number, name: string): Promise<Agent> {
        const { device } = this;

        const agent = await Agent.inject(device, pid, name, this.#delegate, this.#application);
        this.#agents.set(pid, agent);

        this.#delegate.onConsoleMessage("application", LogLevel.Info, `Attached PID: ${name}:${pid}@${device.name}`);

        agent.events.once("uninjected", (reason: SessionDetachReason) => {
            this.#agents.delete(pid);

            const name = this.#processes.get(pid);
            if (name !== undefined) {
                this.#processes.delete(pid);

                switch (reason) {
                    case SessionDetachReason.ApplicationRequested:
                        break;
                    case SessionDetachReason.ProcessReplaced:
                        return;
                    case SessionDetachReason.ProcessTerminated:
                        this.#delegate.onConsoleMessage("application", LogLevel.Warning,
                            `Detached PID: ${name}:${pid}@${device.name}, ${this.#processes.size} remaining`);

                        if (this.#processes.size === 0) {
                            this.#delegate.onConsoleMessage("application", LogLevel.Warning,
                                `All processes lost on host: ${device.name}`);
                        }

                        break;
                    case SessionDetachReason.ConnectionTerminated:
                    case SessionDetachReason.DeviceLost:
                        const message = reason[0].toUpperCase() + reason.substr(1).replace(/-/g, " ");
                        this.#onFailure(new Error(message));
                        break;
                    default:
                }
            }

            if (this.#enlistTask === null && this.#agents.size === 0) {
                this.#onSuccess();
            }
        });

        return agent;
    }

    async #disableSpawnGating(): Promise<void> {
        const { device } = this;

        this.#onSpawnGatingDisabled(new Error("Spawn gating disabled"));

        try {
            await device.disableSpawnGating();
            const pendingSpawns = await device.enumeratePendingSpawn();
            for (const pending of pendingSpawns) {
                await device.resume(pending.pid);
            }
        } catch (e) {
        }
    }

    #onChildAdded = async (child: Child): Promise<void> => {
        const { device } = this;

        try {
            try {
                let name: string | null = null;

                const { path } = child;
                if (path !== null) {
                    name = path;
                }

                const { identifier } = child;
                if (identifier !== null) {
                    name = identifier;
                }

                if (name === null && child.origin === "fork") {
                    const parent = this.#agents.get(child.parentPid);
                    if (parent !== undefined) {
                        name = parent.name;
                    }
                }

                if (name === null) {
                    name = "<unknown>";
                }

                name += ` from ${child.origin}`;

                const agent = await this.#instrument(child.pid, name);

                await agent.scheduler.perform("Resuming", (): Promise<void> => {
                    return device.resume(child.pid);
                });
            } finally {
            }
        } catch (error) {
            console.error(`Oops: ${(error as Error).stack}`);

            try {
                await device.resume(child.pid);
            } catch (error) {
            }
        }
    };

    async #findNamedProcesses(targetProcessName: string): Promise<Process[]> {
        const processes = await this.device.enumerateProcesses(undefined, this.#cancellable);
        const untraced = processes.filter(process => !this.#agents.has(process.pid));
        return untraced.filter(process => process.name === targetProcessName);
    }

    async #findNumberedProcesses(targetProcess: TargetProcessById): Promise<Process[]> {
        const processes = await this.device.enumerateProcesses({}, this.#cancellable);
        const processesById = new Map<number, Process>(processes.map(p => [p.pid, p]));

        const notFound = targetProcess.ids.filter(pid => !processesById.has(pid));
        if (notFound.length !== 0) {
            throw new Error(`Failed to find PIDs: ${notFound.join(', ')}`);
        }

        return targetProcess.ids.map(pid => processesById.get(pid)!);
    }

    async #enlistNewProcesses(targets: TargetProcessAllByName[]): Promise<void> {
        while (!this.#cancellable.isCancelled) {
            for (const target of targets) {
                try {
                    const processes = await this.#findNamedProcesses(target.name);
                    for (let process of processes) {
                        if (!this.#processes.has(process.pid)) {
                            this.#processes.set(process.pid, process);

                            await this.#instrument(process.pid, process.name);
                        }
                    }
                } catch (e) {
                    this.#delegate.onConsoleMessage(target.name, LogLevel.Warning, (e as Error).message);
                }
            }

            await new Promise(resolve => {
                setTimeout(resolve, 500);
            });
        }
    }

    async #getProcesses(targetProcess: TargetProcess): Promise<Process[]> {
        const { device } = this;

        let pid: number;
        switch (targetProcess.kind) {
            case "spawn":
                pid = await this.#scheduler.perform(`Spawning "${targetProcess.program}"`, (): Promise<number> => {
                    return device.spawn(targetProcess.program);
                });
                break;
            case "by-ids":
                return this.#scheduler.perform(`Resolving "${targetProcess.ids.join(", ")}"`, async (): Promise<Process[]> => {
                    return await this.#findNumberedProcesses(targetProcess);
                });
            case "by-name":
                return this.#scheduler.perform(`Resolving "${targetProcess.name}"`, async (): Promise<Process[]> => {
                    return [await device.getProcess(targetProcess.name, undefined, this.#cancellable)];
                });
            case "all-by-name":
                return this.#scheduler.perform(`Resolving "${targetProcess.name}"`, async (): Promise<Process[]> => {
                    return this.#findNamedProcesses(targetProcess.name);
                });
            case "any-by-name":
                return this.#scheduler.perform(`Resolving "${targetProcess.name}"`, async (): Promise<Process[]> => {
                    return this.#findNamedProcesses(targetProcess.name).then((targetProcesses) => {
                        if (targetProcesses.length === 0) {
                            throw new Error(`Failed to find process "${targetProcess.name}" on host "${this.device.name}"`)
                        }
                        return [targetProcesses[0]];
                    });
                });
            case "by-gating":
                return await this.#scheduler.perform(`Waiting for "${targetProcess.name}"`, (): Promise<Process[]> => {
                    return new Promise((resolve, reject) => {
                        this.#onSpawnGatingDisabled = fatReject;

                        const onSpawnAdded: SpawnAddedHandler = async (spawn) => {
                            const { identifier, pid } = spawn;

                            const processes = await device.enumerateProcesses(undefined, this.#cancellable);
                            const proc = processes.find(p => p.pid === pid);
                            if (proc === undefined) {
                                device.resume(pid);
                                return;
                            }

                            if (identifier === targetProcess.name || proc.name === targetProcess.name) {
                                resolve([proc]);
                                return;
                            }

                            device.resume(pid);
                        };

                        device.spawnAdded.connect(onSpawnAdded);

                        device.enableSpawnGating()
                            .catch(fatReject);

                        function fatReject(error: Error) {
                            device.spawnAdded.disconnect(onSpawnAdded);
                            reject(error);
                        }
                    });
                });
            case "by-frontmost":
                const frontmost = await device.getFrontmostApplication(undefined, this.#cancellable);
                if (frontmost === null) {
                    throw new Error(`No frontmost application on ${device.name}`);
                }
                pid = frontmost.pid;
                break;
            default:
                throw new Error("Invalid target process");
        }

        const processes = await device.enumerateProcesses(undefined, this.#cancellable);
        const proc = processes.find((p: Process) => p.pid === pid);
        if (proc === undefined) {
            throw new Error("Process not found");
        }

        return [proc];
    }
}

export interface Delegate {
    onProgress(operation: Operation): void;
    onConsoleMessage(scope: string, level: LogLevel, text: string): void;
}

class Agent {
    scheduler: OperationScheduler;
    events: EventEmitter = new EventEmitter();

    #delegate: Delegate;
    #application: Application;

    #session: Session | null = null;
    #script: Script | null = null;
    #api: AgentApi | null = null;

    constructor(
            public device: string,
            public pid: number,
            public name: string,
            delegate: Delegate,
            application: Application) {
        this.scheduler = new OperationScheduler(`${this.name}:${this.pid}@${this.device}`, delegate);

        this.#delegate = delegate;
        this.#application = application;
    }

    public static async inject(device: Device, pid: number, name: string, delegate: Delegate, application: Application): Promise<Agent> {
        const agent = new Agent(device.name, pid, name, delegate, application);
        const { scheduler } = agent;

        try {
            const session = await scheduler.perform(`Attaching to PID ${name}:${pid}@${device.name}`, (): Promise<Session> => {
                return device.attach(pid);
            });
            agent.#session = session;
            session.detached.connect(agent.#onDetached);
            await scheduler.perform("Enabling child gating", (): Promise<void> => {
                return session.enableChildGating();
            });

            const code = await readFile(new URL("./agent.js", import.meta.url).pathname, "utf-8");
            const script = await scheduler.perform("Creating script", (): Promise<Script> => {
                return session.createScript(code, { runtime: ScriptRuntime.QJS });
            });
            agent.#script = script;
            script.logHandler = agent.#onConsoleMessage;
            script.message.connect(agent.#onMessage);
            await scheduler.perform("Loading script", (): Promise<void> => {
                return script.load();
            });

            agent.#api = script.exports as any as AgentApi;

            await scheduler.perform("Initializing", (): Promise<void> => {
                return (agent.#api as AgentApi).init();
            });
        } catch (e) {
            await agent.dispose();
            throw e;
        }

        return agent;
    }

    public async dispose() {
        const script = this.#script;
        if (script !== null) {
            this.#script = null;

            await this.scheduler.perform("Unloading script", async (): Promise<void> => {
                try {
                    await script.unload();
                } catch (error) {
                }
            });
        }

        const session = this.#session;
        if (session !== null) {
            this.#session = null;

            await this.scheduler.perform("Detaching", async (): Promise<void> => {
                try {
                    await session.detach();
                } catch (error) {
                }
            });
        }
    }

    #onDetached = (reason: SessionDetachReason): void => {
        this.events.emit("uninjected", reason);
    };

    #onConsoleMessage = (level: LogLevel, text: string): void => {
        this.#delegate.onConsoleMessage(`${this.name}:${this.pid}@${this.device}`, level, text);
    };

    #onMessage = (message: Message, data: Buffer | null): void => {
        switch (message.type) {
            case MessageType.Send:
                if (message.payload.type === "trace") {
                    this.#application.onTrace(message.payload, data!, this.#api!);
                    return;
                }
                console.error(`[PID=${this.pid}]:`, message.payload);
                break;
            case MessageType.Error:
                console.error(`[PID=${this.pid}]:`, message.stack);
                break;
            default:
        }
    };
}

class OperationScheduler {
    #scope: string;
    #delegate: Delegate;

    constructor(scope: string, delegate: Delegate) {
        this.#scope = scope;
        this.#delegate = delegate;
    }

    public async perform<T>(description: string, work: () => Promise<T>): Promise<T> {
        let result: T;

        const operation = new AsyncOperation(this.#scope, description);
        this.#delegate.onProgress(operation);

        try {
            result = await work();

            operation.complete();
        } catch (error) {
            operation.complete(error as Error);
            throw error;
        }

        return result;
    }
}
