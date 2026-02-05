const sss = require('../lib'),
    rl = require('readline'),
    path = require('path');

const terminationHandler = () => {
    process.exit(1);
};

process.on('SIGTERM', terminationHandler);
process.on('SIGINT', terminationHandler);

const parentDir = path.dirname(__dirname);
const buildPath = path.join(parentDir, 'build');

const runProgram = async (time_sec, memory_pages) => {
    try {
        const rootfs = "/"
        const sandboxedProcess = sss.startSandbox({
            hostname: "qwq",
            chroot: rootfs,
            mounts: [],
            executable: `/busy`,
            parameters: [`/busy`, time_sec.toString(), memory_pages.toString()],
            environments: ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            stdin: "/dev/stdin",
            stdout: "/dev/stdout",
            stderr: "/dev/stdout",
            time: 2 * 1000, 
            mountProc: true,
            redirectBeforeChroot: true,
            memory: 102400 * 1024, // 100MB
            process: 30,
            user: sss.getUidAndGidInSandbox(rootfs, "nobody"),
            cgroup: "asdf",
            workingDirectory: '/'
        });

        // Uncomment these and change 'stdin: "/dev/stdin"' to "/dev/null" to cancel the sandbox with enter
        //
        // console.log("Sandbox started, press enter to stop");
        // var stdin = process.openStdin();
        // stdin.addListener("data", function (d) {
        //     sandboxedProcess.stop();
        // });

        const result = await sandboxedProcess.waitForStop();
        return result;
    } catch (ex) {
        console.log("Whooops! " + ex.toString());
    }
    process.exit();
};

const testSandbox = async () => {
    // Normal
    const result_ok = await runProgram(1, Math.floor(50 * 1024 / 4)); // 1s, 50MiB
    console.log("Normal sandbox finished!" + JSON.stringify(result_ok));
    // TLE
    const result_tle = await runProgram(3, Math.floor(50 * 1024 / 4)); // 2s, 50MiB
    console.log("TLE sandbox finished!" + JSON.stringify(result_tle));
    // MLE
    const result_mle = await runProgram(1, Math.floor(200 * 1024 / 4)); // 1s, 200MiB
    console.log("MLE sandbox finished!" + JSON.stringify(result_mle));
}

testSandbox();
