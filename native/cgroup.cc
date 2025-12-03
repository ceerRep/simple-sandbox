#include <string>
#include <vector>
#include <list>
#include <algorithm>
#include <map>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include <filesystem>

#include <mntent.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>

#include <fmt/format.h>
#include <fmt/ostream.h>
#include <fmt/os.h>

#include "utils.h"
#include "cgroup.h"

using std::string;
using std::vector;
using std::list;
using std::map;
using std::ifstream;
using std::ofstream;
namespace fs = std::filesystem;
using fmt::format;

const map<string, vector<fs::path>> cgroup_mnt = InitializeCgroup();

static bool IsEmpty(const string &str)
{
    auto f = [](unsigned char const c) { return std::isspace(c); };
    return std::all_of(str.begin(), str.end(), f);
}
CgroupInfo::CgroupInfo(const string &group)
    : Group(group)
{
    if (IsEmpty(group))
    {
        throw std::invalid_argument("Group name cannot be empty!");
    }
}

// This piece of code is copied from libcgroup but translated to C++. C++ is very great.
map<string, vector<fs::path>> InitializeCgroup()
{
    map<string, vector<fs::path>> cgroup_mnt;

    char buf[4 * FILENAME_MAX];
    // cgroup v2 has a single unified hierarchy mounted as type "cgroup2".

    std::unique_ptr<FILE, decltype(fclose) *> proc_mount(CHECKNULL(fopen("/proc/mounts", "re")), fclose);
    std::unique_ptr<mntent> temp_ent = std::make_unique<mntent>();
    mntent *ent;
    while ((ent = getmntent_r(proc_mount.get(), temp_ent.get(),
                              buf,
                              sizeof(buf))) != NULL)
    {
        // Prefer unified cgroup v2
        if (strcmp(ent->mnt_type, "cgroup2") == 0)
        {
            cgroup_mnt["unified"].push_back(fs::path(string(ent->mnt_dir)));
        }
    }

    return cgroup_mnt;
}

static const fs::path &GetPath()
{
    // In v2, all controllers reside in the unified mount.
    auto mnts = cgroup_mnt.find("unified");
    if (mnts == cgroup_mnt.end())
    {
        throw std::invalid_argument("cgroup v2 unified mount not found.");
    }
    return (mnts->second)[0];
}

static fs::path EnsureGroup(const CgroupInfo &info)
{
    fs::path groupDirectory = GetPath() / info.Group;
    if (!fs::exists(groupDirectory) || !fs::is_directory(groupDirectory))
    {
        throw std::runtime_error((format("Path {} is not valid (does not exist or is not a directory).", groupDirectory)));
    }
    return groupDirectory;
}

template <typename T>
static void WriteFile(const fs::path &path, T val, bool overwrite)
{
    ofstream ofs;
    ofs.exceptions(std::ios::failbit | std::ios::badbit);
    auto flags = ofstream::out | (overwrite ? ofstream::trunc : ofstream::app);
    ofs.open(path, flags);
    ofs << val << std::endl;
}

static void ReadArray64(const fs::path &path, list<int64_t> &cc)
{
    ifstream ifs;
    // No fail bit; just ignore when failed.
    ifs.exceptions(std::ios::badbit);
    ifs.open(path);
    cc.clear();
    int64_t val;
    while (ifs >> val)
    {
        cc.push_back(val);
    }
}

static int64_t ReadInt64(const fs::path &path)
{
    ifstream ifs;
    ifs.exceptions(std::ios::failbit | std::ios::badbit);
    ifs.open(path);
    int64_t val;
    ifs >> val;
    return val;
}

void CreateGroup(const CgroupInfo &info)
{
    auto groupDirectory = GetPath() / info.Group;

    if (!fs::exists(groupDirectory))
    {
        fs::create_directories(groupDirectory);
    }
    else if (!fs::is_directory(groupDirectory))
    {
        throw std::runtime_error((format("Path {} has already been used and is not a directory.", groupDirectory)));
    }

    // Add memory and pid controllers to the group
    std::filesystem::path cur;
    for (auto &part : std::filesystem::path(info.Group)) {
        cur /= part;
        auto curDir = GetPath() / cur;

        if (curDir == groupDirectory)
            break;
        
        WriteGroupProperty(CgroupInfo(cur.string()), "cgroup.subtree_control", "+memory +pids", false);
    }
}

int64_t ReadGroupProperty(const CgroupInfo &info, const string &property)
{
    auto groupDir = EnsureGroup(info);
    return ReadInt64(groupDir / property);
}

list<int64_t> ReadGroupPropertyArray(const CgroupInfo &info, const string &property)
{
    auto groupDir = EnsureGroup(info);
    list<int64_t> val;
    ReadArray64(groupDir / property, val);
    return val;
}

map<string, int64_t> ReadGroupPropertyMap(const CgroupInfo &info, const string &property)
{
    auto groupDir = EnsureGroup(info);
    map<string, int64_t> result;
    ifstream ifs;
    ifs.exceptions(std::ios::badbit);
    ifs.open(groupDir / property);
    while (ifs)
    {
        string name;
        ifs >> name;
        int64_t val;
        ifs >> val;
        result.insert(std::pair<string, int64_t>(name, val));
    }
    return result;
}

void KillGroupMembers(const CgroupInfo &info)
{
    // cgroup v2 supports bulk kill via cgroup.kill
    auto groupDir = EnsureGroup(info);
    try
    {
        WriteFile(groupDir / "cgroup.kill", 1, true);
        return;
    }
    catch (...)
    {
        // Fallback to iterating processes if cgroup.kill not available
    }
    auto v = ReadGroupPropertyArray(info, "cgroup.procs");
    for (auto &item : v)
    {
        ENSURE(kill((int)(item), SIGKILL));
    }
}

void RemoveCgroup(const CgroupInfo &info)
{
    KillGroupMembers(info);
    auto groupDir = EnsureGroup(info);
    rmdir(groupDir.c_str());
}

void WriteGroupProperty(const CgroupInfo &info, const string &property, int64_t val, bool overwrite)
{
    auto groupDir = EnsureGroup(info);
    if (val < 0)
    {
        return WriteFile(groupDir / property, string("max"), overwrite);
    }
    else
    {
        return WriteFile(groupDir / property, val, overwrite);
    }
}

void WriteGroupProperty(const CgroupInfo &info, const string &property, const string &val, bool overwrite)
{
    auto groupDir = EnsureGroup(info);
    return WriteFile(groupDir / property, val, overwrite);
}
