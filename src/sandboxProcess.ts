import { SandboxParameter, SandboxResult, SandboxStatus } from './interfaces';
import sandboxAddon from './nativeAddon';

export class SandboxProcess {
    private readonly timeoutHandle: NodeJS.Timeout | null = null;
    private readonly stopCallback: () => void;

    private timeout: boolean = false;
    private cancelled: boolean = false;
    private waitPromise: Promise<SandboxResult> = null;

    public running: boolean = true;

    constructor(
        public readonly parameter: SandboxParameter,
        public readonly pid: number,
        execParam: ArrayBuffer
    ) {
        const myFather = this;
        // Stop the sandboxed process on Node.js exit.
        this.stopCallback = () => {
            myFather.stop();
        };

        process.on('exit', this.stopCallback);

        // Timeout: real time + 0.5s, then kill process group.
        if (this.parameter.time !== -1) {
            const limitMs = this.parameter.time * 1.5 + 3000;
            this.timeoutHandle = setTimeout(() => {
                myFather.timeout = true;
                myFather.stop();
            }, limitMs);
        }

        this.waitPromise = new Promise((res, rej) => {
            sandboxAddon.waitForProcess(pid, execParam, (err, runResult) => {
                if (err) {
                    try {
                        myFather.stop();
                        myFather.cleanup();
                    } catch (e) {
                        console.log("Error cleaning up error sandbox:", e);
                    }
                    rej(err);
                } else {
                    try {
                        myFather.cleanup();

                        const result: SandboxResult = {
                            status: SandboxStatus.Unknown,
                            time: runResult.time,
                            memory: runResult.memory,
                            code: runResult.code
                        };

                        if (result.time / 1e6 > myFather.parameter.time) {
                            myFather.timeout = true;
                        }

                        if (myFather.timeout) {
                            result.status = SandboxStatus.TimeLimitExceeded;
                        } else if (myFather.cancelled) {
                            result.status = SandboxStatus.Cancelled;
                        } else if (myFather.parameter.memory != -1 && runResult.memory > myFather.parameter.memory) {
                            result.status = SandboxStatus.MemoryLimitExceeded;
                        } else if (runResult.status === 'signaled') {
                            result.status = SandboxStatus.RuntimeError;
                        } else if (runResult.status === 'exited') {
                            result.status = SandboxStatus.OK;
                        }

                        res(result);
                    } catch (e) {
                        rej(e);
                    }
                }
            });
        });
    }

    private cleanup(): void {
        if (this.running) {
            if (this.timeoutHandle) {
                clearTimeout(this.timeoutHandle);
            }
            process.removeListener('exit', this.stopCallback);
            this.running = false;
        }
    }

    stop(): void {
        this.cancelled = true;
        try {
            sandboxAddon.killProcessGroup(this.pid);
        } catch (err) {}
    }

    async waitForStop(): Promise<SandboxResult> {
        return await this.waitPromise;
    }
};
