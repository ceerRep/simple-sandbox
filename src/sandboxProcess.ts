import { SandboxParameter, SandboxResult, SandboxStatus } from './interfaces';
import sandboxAddon from './nativeAddon';
import * as utils from './utils';

export class SandboxProcess {
    private readonly cancellationToken: NodeJS.Timer = null;
    private readonly stopCallback: () => void;

    private countedCpuTime: number = 0; // accumulated, in ns
    private actualCpuTime: number = 0;  // last observed, in ns
    private baselinecpuUsageUs: number = 0; // initial cpu usage (ns)
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
        }

        this.baselinecpuUsageUs = 0;

        let checkIfTimedOut = () => { };
        if (this.parameter.time !== -1) {
            // Check every 50ms.
            const checkInterval = Math.min(this.parameter.time / 10, 50);
            let lastCheck = new Date().getTime();
            checkIfTimedOut = () => {
                let current = new Date().getTime();
                const spent = current - lastCheck;
                lastCheck = current;
                // cgroup v2: cpu.stat usage_usec
                myFather.updateBaseline(execParam);
                const cpuUsec: number = Number(sandboxAddon.getCgroupProperty2(myFather.parameter.cgroup, "cpu.stat", "usage_usec")) - myFather.baselinecpuUsageUs;
                const val: number = cpuUsec; // us
                myFather.countedCpuTime += Math.max(
                    (val - myFather.actualCpuTime) * 1000, // ns  
                    utils.milliToNano(spent) * 0.4 // 40% of actually elapsed time
                );
                myFather.actualCpuTime = val;

                // Time limit exceeded
                if (myFather.countedCpuTime > utils.milliToNano(parameter.time)) {
                    myFather.timeout = true;
                    myFather.stop();
                }
            };
            this.cancellationToken = setInterval(checkIfTimedOut, checkInterval);
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
                        // cgroup v2: memory.peak and cpu.stat usage_usec; compute deltas from baseline
                        const memUsage: number = Number(sandboxAddon.getCgroupProperty(myFather.parameter.cgroup, "memory.peak"));

                        const cpuUsecEnd: number = Number(sandboxAddon.getCgroupProperty2(myFather.parameter.cgroup, "cpu.stat", "usage_usec"));
                        myFather.actualCpuTime = (cpuUsecEnd - myFather.baselinecpuUsageUs) * 1000;
                        myFather.cleanup();
    
                        const result: SandboxResult = {
                            status: SandboxStatus.Unknown,
                            time: myFather.actualCpuTime,
                            memory: memUsage,
                            code: runResult.code
                        };
    
                        if (myFather.timeout || myFather.actualCpuTime > utils.milliToNano(myFather.parameter.time)) {
                            result.status = SandboxStatus.TimeLimitExceeded;
                        } else if (myFather.cancelled) {
                            result.status = SandboxStatus.Cancelled;
                        } else if (myFather.parameter.memory != -1 && memUsage > myFather.parameter.memory) {
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
            })
        });
    }

    private updateBaseline(execParam: ArrayBuffer): void {
        const b = sandboxAddon.getCgroupBaselines(execParam);
        this.baselinecpuUsageUs = Number(b.cpuUsageUs) || 0;
    }

    private removeCgroup(): void {
        // cgroup v2 unified removal
        sandboxAddon.removeCgroup(this.parameter.cgroup);
    }

    private cleanup(): void {
        if (this.running) {
            if (this.cancellationToken) {
                clearInterval(this.cancellationToken);
            }
            process.removeListener('exit', this.stopCallback);
            this.removeCgroup();
            this.running = false;
        }
    }

    stop(): void {
        this.cancelled = true;
        try {
            process.kill(this.pid, "SIGKILL");
        } catch (err) {}
    }

    async waitForStop(): Promise<SandboxResult> {
        return await this.waitPromise;
    }
};
