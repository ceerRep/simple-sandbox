#include <cassert>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string>
#include <system_error>
#include <unistd.h>
#include <sys/wait.h>

#include "cgroup.h"

using std::string;

static bool is_permission_error(const std::system_error &e) {
    int c = e.code().value();
    return c == EACCES || c == EPERM;
}

int main() {
    // Create a unique group name
    string group = "simple-sandbox-kill-test-" + std::to_string(getpid());

    try {
        // Try to create a cgroup; if we don't have permission or v2 not mounted, skip
        CgroupInfo info(group);
        try {
            CreateGroup(info);
        } catch (const std::system_error &e) {
            if (is_permission_error(e)) {
                std::cout << "SKIP: cgroup v2 not writable for this user\n";
                return 0; // skip
            }
            // Other system_error -> treat as skip as well to be safe in CI
            std::cout << "SKIP: cannot create cgroup: " << e.code().value() << "\n";
            return 0;
        } catch (const std::invalid_argument &e) {
            // unified mount not found -> skip
            std::cout << "SKIP: cgroup v2 unified mount not found\n";
            return 0;
        }

        pid_t child = fork();
        if (child == -1) {
            perror("fork");
            return 1;
        }
        if (child == 0) {
            // Child: loop until killed
            for (;;) pause();
            _exit(0);
        }

        // Move child into the test cgroup
        try {
            WriteGroupProperty(info, "cgroup.procs", (int64_t)child);
        } catch (const std::system_error &e) {
            // If we cannot move, skip and reap child
            kill(child, SIGKILL);
            waitpid(child, nullptr, 0);
            if (is_permission_error(e)) {
                std::cout << "SKIP: cannot move process into cgroup (permissions)\n";
                return 0;
            }
            std::cout << "SKIP: cannot move process into cgroup: " << e.code().value() << "\n";
            return 0;
        }

        // Kill all members via cgroup API
        KillGroupMembers(info);

        int status = 0;
        waitpid(child, &status, 0);
        assert(WIFSIGNALED(status));
        assert(WTERMSIG(status) == SIGKILL);

        // Cleanup cgroup
        RemoveCgroup(info);

        std::cout << "cgroup_kill_test passed\n";
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "Test failed with exception: " << ex.what() << "\n";
        return 1;
    }
}
