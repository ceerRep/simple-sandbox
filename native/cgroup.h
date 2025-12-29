#pragma once
// This is a simple version of libcgroup.
// The libcgroup itself is complicated and not very well documented, so here I implement a new one.
// This one only fits the sandbox and does not have a general-purpose design.

#include <string>
#include <list>
#include <map>
#include <optional>
#include <filesystem>

struct CgroupInfo
{
    std::string Group;
    explicit CgroupInfo(const std::string &group);
};

// Look for mount paths.
std::optional<std::filesystem::path> InitializeCgroup();

void CreateGroup(const CgroupInfo &info);

int64_t ReadGroupProperty(const CgroupInfo &info, const std::string &property);
std::list<int64_t> ReadGroupPropertyArray(const CgroupInfo &info, const std::string &property);
std::map<std::string, int64_t> ReadGroupPropertyMap(const CgroupInfo &info, const std::string &property);

void WriteGroupProperty(const CgroupInfo &info, const std::string &property, int64_t val, bool overwrite = true);
void WriteGroupProperty(const CgroupInfo &info, const std::string &property, const std::string& val, bool overwrite = true);
void RemoveCgroup(const CgroupInfo &info);

// Kill all existing tasks in a group.
void KillGroupMembers(const CgroupInfo &info);
