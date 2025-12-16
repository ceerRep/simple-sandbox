import { SandboxParameter } from './interfaces';
import nativeAddon from './nativeAddon';
import { SandboxProcess } from './sandboxProcess';
import { existsSync } from 'fs';
import * as randomString from 'randomstring';
import * as path from 'path';

export * from './interfaces';

// Require cgroup v2 unified hierarchy
if (!existsSync('/sys/fs/cgroup/cgroup.controllers')) {
    throw new Error("Cgroup v2 unified hierarchy is required.");
}

const MAX_RETRY_TIMES = 20;
export function startSandbox(parameter: SandboxParameter): SandboxProcess {
    const doStart = () => {
        const actualParameter = Object.assign({}, parameter);
        actualParameter.cgroup = path.join(actualParameter.cgroup, randomString.generate(9));
        const startResult: { pid: number; execParam: ArrayBuffer } = nativeAddon.startSandbox(actualParameter);
        return new SandboxProcess(actualParameter, startResult.pid, startResult.execParam);
    };

    let retryTimes = MAX_RETRY_TIMES;
    while (1) {
        try {
            return doStart();
        } catch (e) {
            // Retry if the child process fails
            if ("message" in e && typeof e.message === "string" && e.message.startsWith("The child process ")) {
                if (retryTimes-- > 0)
                    continue;
            }

            throw e;
        }
    }
};

export function getUidAndGidInSandbox(rootfs: string, username: string): { uid: number; gid: number } {
    try {
        return nativeAddon.getUidAndGidInSandbox(rootfs, username);
    } catch (e) {
        throw e;
    }
}

export function pipe(): { read: number; write: number } {
    try {
        return nativeAddon.unixPipe();
    } catch (e) {
        throw e;
    }
}
