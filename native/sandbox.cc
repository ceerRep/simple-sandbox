#include <string>
#include <system_error>
#include <vector>
#include <stdexcept>
#include <memory>

#include <cstring>
#include <cassert>

#include <filesystem>

#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <syscall.h>
#include <grp.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <cerrno>

#include <seccomp.h>

#include <fmt/format.h>
#include <fmt/ostream.h>
#include <fmt/os.h>

#include "sandbox.h"
#include "utils.h"
#include "semaphore.h"
#include "pipe.h"

#include <iostream>

namespace fs = std::filesystem;
using std::string;
using std::vector;
using fmt::format;

// Make sure fd 0,1,2 exists.
static void RedirectIO(const SandboxParameter &param, int nullfd)
{
    const string &std_input = param.stdinRedirection,
                 std_output = param.stdoutRedirection,
                 std_error = param.stderrRedirection;

    int inputfd, outputfd, errorfd;
    if (param.stdinRedirectionFileDescriptor == -1)
    {
        if (std_input != "")
        {
            inputfd = ENSURE(open(std_input.c_str(), O_RDONLY));
        }
        else
        {
            inputfd = nullfd;
        }
    }
    else
    {
        inputfd = param.stdinRedirectionFileDescriptor;
    }
    ENSURE(dup2(inputfd, STDIN_FILENO));

    if (param.stdoutRedirectionFileDescriptor == -1)
    {
        if (std_output != "")
        {
            outputfd = ENSURE(open(std_output.c_str(), O_WRONLY | O_TRUNC | O_CREAT,
                                   S_IWUSR | S_IRUSR | S_IRGRP | S_IWGRP));
        }
        else
        {
            outputfd = nullfd;
        }
    }
    else
    {
        outputfd = param.stdoutRedirectionFileDescriptor;
    }
    ENSURE(dup2(outputfd, STDOUT_FILENO));

    if (param.stderrRedirectionFileDescriptor == -1)
    {
        if (std_error != "")
        {
            if (std_error == std_output)
            {
                errorfd = outputfd;
            }
            else
            {
                errorfd = ENSURE(open(std_error.c_str(), O_WRONLY | O_TRUNC | O_CREAT,
                                      S_IWUSR | S_IRUSR | S_IRGRP | S_IWGRP));
            }
        }
        else
        {
            errorfd = nullfd;
        }
    }
    else
    {
        errorfd = param.stderrRedirectionFileDescriptor;
    }
    ENSURE(dup2(errorfd, STDERR_FILENO));
}

struct ExecutionParameter
{
    const SandboxParameter &parameter;

    PosixSemaphore semaphore1, semaphore2;
    // This pipe is used to forward error message from the child process to the parent.
    PosixPipe pipefd;

    ExecutionParameter(const SandboxParameter &param, int pipeOptions) : parameter(param),
                                                                         semaphore1(true, 0),
                                                                         semaphore2(true, 0),
                                                                         pipefd(pipeOptions)
    {
    }
};

// Install seccomp filter via libseccomp: deny setsid, setpgid; deny socket/socketpair
// only for AF_INET/AF_INET6 (setpgrp covered by setpgid; AF_UNIX allowed for runtime/NSS).
// libseccomp sets PR_SET_NO_NEW_PRIVS and handles arch/nr offsets. Installed after setuid;
// if seccomp_load fails with EPERM (e.g. LSM), consider moving before setuid, after chroot.
static void InstallSeccompFilter()
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == nullptr)
        throw std::runtime_error("seccomp_init failed");

    auto release_ctx = [](scmp_filter_ctx *p) {
        if (p)
            seccomp_release(*p);
    };
    std::unique_ptr<scmp_filter_ctx, decltype(release_ctx)> ctx_guard(&ctx, release_ctx);

    Ensure_Seccomp(seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setsid), 0));
    Ensure_Seccomp(seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(setpgid), 0));

    Ensure_Seccomp(seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(socket), 1,
                                   SCMP_A0(SCMP_CMP_EQ, AF_INET)));
    Ensure_Seccomp(seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(socket), 1,
                                   SCMP_A0(SCMP_CMP_EQ, AF_INET6)));
    Ensure_Seccomp(seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(socketpair), 1,
                                   SCMP_A0(SCMP_CMP_EQ, AF_INET)));
    Ensure_Seccomp(seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(socketpair), 1,
                                   SCMP_A0(SCMP_CMP_EQ, AF_INET6)));
    Ensure_Seccomp(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0));
    Ensure_Seccomp(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
                                   SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_PARENT, CLONE_PARENT)));

    Ensure_Seccomp(seccomp_load(ctx));
    // ctx_guard frees ctx on return
}

static void EnsureDirectoryExistance(fs::path dir) {
    if (!fs::exists(dir))
    {
        throw std::runtime_error((format("The specified path {} does not exist.", dir)));
    }
    if (!fs::is_directory(dir))
    {
        throw std::runtime_error((format("The specified path {} exists, but is not a directory.", dir)));
    }
}

void GetUserEntryInSandbox(const fs::path &rootfs, const std::string username, std::vector<char> &dataBuffer, passwd &entry) {
    auto passwdFilePath = rootfs / "etc" / "passwd";
    std::unique_ptr<FILE, decltype(&fclose)> passwdFile(fopen(passwdFilePath.c_str(), "r"), &fclose);
    if (passwdFile == nullptr) {
        throw std::system_error(errno, std::system_category(), "Couldn't open /etc/passwd in rootfs");
    }

    long passwdBufferSize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (passwdBufferSize == -1) { passwdBufferSize = 16384; }
    dataBuffer.resize(passwdBufferSize);

    passwd *user = nullptr;
    while (fgetpwent_r(passwdFile.get(), &entry, dataBuffer.data(), passwdBufferSize, &user) == 0) {
        if (username == user->pw_name) {
            break;
        }
    }

    if (user == nullptr) {
        if (errno == ENOENT) {
            throw std::invalid_argument(format("No such user: {}", username));
        } else {
            throw std::system_error(errno, std::system_category(), "fgetpwent_r");
        }
    }
}

static int ChildProcess(void *param_ptr)
{
    ExecutionParameter &execParam = *reinterpret_cast<ExecutionParameter *>(param_ptr);
    // We obtain a full copy of parameters here. The arguments may be destoryed after some time.
    SandboxParameter parameter = execParam.parameter;

    try
    {
        ENSURE(close(execParam.pipefd[0]));

        if (!execParam.parameter.cpuAffinity.empty()) {
            cpu_set_t mask;
            CPU_ZERO(&mask);
            for (auto cpu : execParam.parameter.cpuAffinity)
                CPU_SET(cpu, &mask);
            ENSURE(sched_setaffinity(0, sizeof(cpu_set_t), &mask));
        }

        int nullfd = ENSURE(open("/dev/null", O_RDWR));
        if (parameter.redirectBeforeChroot)
        {
            RedirectIO(parameter, nullfd);
        }

        for (MountInfo &info : parameter.mounts)
        {
            if (!info.dst.is_absolute()) {
                throw std::invalid_argument(format("The dst path {} in mounts should be absolute.", info.dst));
            }

            fs::path target = parameter.chrootDirectory / info.dst;
            fmt::print("Symlinking {} to {}\n", info.src, target);
	    
            EnsureDirectoryExistance(info.src);

            // In a normal container, cannot do bind mount
            // Use symlink to achieve the same effect.
            std::error_code ec;
            fs::remove(target, ec);
            ENSURE(symlink(info.src.string().c_str(), target.string().c_str()));
        }

        // ENSURE(chroot(parameter.chrootDirectory.string().c_str()));
        ENSURE(chdir(parameter.workingDirectory.string().c_str()));

        if (!parameter.redirectBeforeChroot)
        {
            RedirectIO(parameter, nullfd);
        }

        if (parameter.stackSize != -2)
        {
            rlimit64 rlim;
            rlim.rlim_max = rlim.rlim_cur = parameter.stackSize != -1 ? parameter.stackSize : RLIM64_INFINITY;
            ENSURE(setrlimit64(RLIMIT_STACK, &rlim));
        }

        {
            rlimit rlim;
            rlim.rlim_max = rlim.rlim_cur = 0;
            ENSURE(setrlimit(RLIMIT_CORE, &rlim));
        }

        gid_t groupList[1];
        groupList[0] = parameter.gid;
        ENSURE(syscall(SYS_setgid, parameter.gid));
        ENSURE(syscall(SYS_setgroups, 1, groupList));
        ENSURE(syscall(SYS_setuid, parameter.uid));

        // Limit number of processes (RLIMIT_NPROC is per real UID, so set after setuid).
        // processLimit = max children; total processes = 1 (self) + children, so set limit to processLimit + 1.
        if (parameter.processLimit != -1)
        {
            rlimit rlim;
            rlim.rlim_cur = rlim.rlim_max = static_cast<rlim_t>(parameter.processLimit);
            ENSURE(setrlimit(RLIMIT_NPROC, &rlim));
        }

        // Create new process group so we can kill the whole group later (leader = this process).
        ENSURE(setpgid(0, 0));

        // Forbid setsid/setpgid/setpgrp to prevent escape from process group.
        InstallSeccompFilter();

        vector<char *> params = StringToPtr(parameter.executableParameters),
                       envi = StringToPtr(parameter.environmentVariables);

        int temp = -1;
        // Inform the parent that no exception occurred.
        ENSURE(write(execParam.pipefd[1], &temp, sizeof(int)));

        // Inform our parent that we are ready to go.
        execParam.semaphore1.Post();
        // Wait for parent's reply.
        execParam.semaphore2.Wait();

        ENSURE(execvpe(parameter.executable.c_str(), &params[0], &envi[0]));

        // If execvpe returns, then we meet an error.
        return 1;
    }
    catch (std::exception &err)
    {
        fmt::print("Exception: {}\n", err.what());
        const char *errMessage = err.what();
        int len = strlen(errMessage);
        try
        {
            ENSURE(write(execParam.pipefd[1], &len, sizeof(int)));
            ENSURE(write(execParam.pipefd[1], errMessage, len));
            ENSURE(close(execParam.pipefd[1]));
            execParam.semaphore1.Post();
            return 1;
        }
        catch (...)
        {
            assert(false);
            throw;
        }
    }
    catch (...)
    {
        assert(false);
        throw;
    }
}

// The child stack is only used before `execvpe`, so it does not need much space.
const int childStackSize = 1024 * 700;
void *StartSandbox(const SandboxParameter &parameter,
                   pid_t &container_pid)
{
    container_pid = -1;
    try
    {
        // char* childStack = new char[childStackSize];
        std::vector<char> childStack(childStackSize); // I don't want to call `delete`

        std::unique_ptr<ExecutionParameter> execParam = std::make_unique<ExecutionParameter>(parameter, O_CLOEXEC | O_NONBLOCK);

        // Subreaper so we reap all descendants when the direct child exits.
        ENSURE(prctl(PR_SET_CHILD_SUBREAPER, 1));

        container_pid = ENSURE(clone(ChildProcess, childStack.data() + childStack.size(), SIGCHLD,
                                     const_cast<void *>(reinterpret_cast<const void *>(execParam.get()))));

        // Wait for at most 500ms. If the child process hasn't posted the semaphore,
        // We will assume that the child has already dead.
        bool waitResult = execParam->semaphore1.TimedWait(500);

        int errLen, bytesRead = read(execParam->pipefd[0], &errLen, sizeof(int));
        // Child will be killed once the error has been thrown.
        if (!waitResult || bytesRead == 0 || bytesRead == -1)
        {
            if (waitpid(container_pid, nullptr, WNOHANG) == 0)
            {
                // The child process is still alive.
                throw std::runtime_error("The child process is not responding.");
            }
            // The child process exited with no information available.
            throw std::runtime_error("The child process has exited unexpectedly.");
        }
        else if (errLen != -1) // -1 indicates OK.
        {
            vector<char> buf(errLen);
            ENSURE(read(execParam->pipefd[0], &*buf.begin(), errLen));
            string errstr(buf.begin(), buf.end());
            throw std::runtime_error((format("The child process has reported the following error: {}", errstr)));
        }

        // Continue the child.
        execParam->semaphore2.Post();

        return execParam.release();
    }
    catch (std::exception &ex)
    {
        // Do the cleanups; we don't care whether these operations are successful.
        if (container_pid != -1)
        {
            (void)kill(container_pid, SIGKILL);
            (void)waitpid(container_pid, NULL, WNOHANG);
        }
        std::rethrow_exception(std::current_exception());
    }
}

ExecutionResult
WaitForProcess(pid_t pid, void *executionParameter)
{
    std::unique_ptr<ExecutionParameter> execParam(reinterpret_cast<ExecutionParameter *>(executionParameter));

    ExecutionResult result{};
    result.timeNs = 0;
    result.memoryBytes = 0;

    int status;
    int mainStatus;
    struct rusage ru;
    int64_t maxRssKb = 0;

    // Wait for the direct child (sandbox leader) first.
    ENSURE(wait4(pid, &mainStatus, 0, &ru));

    result.timeNs += static_cast<int64_t>(ru.ru_utime.tv_sec) * 1000000000LL
                   + static_cast<int64_t>(ru.ru_utime.tv_usec) * 1000LL
                   + static_cast<int64_t>(ru.ru_stime.tv_sec) * 1000000000LL
                   + static_cast<int64_t>(ru.ru_stime.tv_usec) * 1000LL;
    if (static_cast<int64_t>(ru.ru_maxrss) > maxRssKb)
        maxRssKb = ru.ru_maxrss;

    // Reap all descendants (reparented to us via PR_SET_CHILD_SUBREAPER). Block until ECHILD.
    pid_t w;
    while ((w = wait4(-1, &status, 0, &ru)) > 0)
    {
        result.timeNs += static_cast<int64_t>(ru.ru_utime.tv_sec) * 1000000000LL
                       + static_cast<int64_t>(ru.ru_utime.tv_usec) * 1000LL
                       + static_cast<int64_t>(ru.ru_stime.tv_sec) * 1000000000LL
                       + static_cast<int64_t>(ru.ru_stime.tv_usec) * 1000LL;
        if (static_cast<int64_t>(ru.ru_maxrss) > maxRssKb)
            maxRssKb = ru.ru_maxrss;
    }
    // w == -1 with errno ECHILD means no more children; other errno is unexpected.
    if (w == -1 && errno != ECHILD)
        throw std::system_error(errno, std::system_category(), "wait4");

    result.memoryBytes = maxRssKb * 1024;

    if (WIFEXITED(mainStatus))
    {
        result.status = EXITED;
        result.code = WEXITSTATUS(mainStatus);
    }
    else if (WIFSIGNALED(mainStatus))
    {
        result.status = SIGNALED;
        result.code = WTERMSIG(mainStatus);
    }
    return result;
}

void KillProcessGroup(pid_t pgid)
{
    (void)kill(-pgid, SIGKILL);
}
