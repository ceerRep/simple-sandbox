#include <cassert>
#include <cerrno>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include "utils.h"

using std::string;
using std::vector;

static void test_StringToPtr()
{
    vector<string> src = {"/bin/echo", "hello", "world"};
    vector<char *> res = StringToPtr(src);

    // Must be null-terminated and size == n + 1
    assert(res.size() == src.size() + 1);
    assert(res.back() == nullptr);

    // Pointers should match contents
    for (size_t i = 0; i < src.size(); ++i)
    {
        assert(std::string(res[i]) == src[i]);
    }
}

static void test_EnsureNot_success()
{
    // When ret != err, value passes through
    int v = EnsureNot(5, -1);
    assert(v == 5);
}

static void test_EnsureNot_failure()
{
    errno = EINVAL;
    bool thrown = false;
    try
    {
        (void)EnsureNot(-1, -1);
    }
    catch (const std::system_error &e)
    {
        thrown = true;
        // EINVAL code expected
        assert(e.code().value() == EINVAL);
    }
    assert(thrown);
}

static void test_Ensure0_success()
{
    // 0 should not throw
    Ensure0(0);
}

static void test_Ensure0_failure()
{
    errno = EBUSY;
    bool thrown = false;
    try
    {
        Ensure0(-1);
    }
    catch (const std::system_error &e)
    {
        thrown = true;
        assert(e.code().value() == EBUSY);
    }
    assert(thrown);
}

static void test_CheckNull_Custom()
{
    int x = 123;
    int *px = &x;
    int *ok = CheckNull_Custom(px, "ptr");
    assert(ok == &x);

    bool thrown = false;
    try
    {
        (void)CheckNull_Custom(static_cast<void *>(nullptr), "ptr");
    }
    catch (const std::runtime_error &)
    {
        thrown = true;
    }
    assert(thrown);
}

int main()
{
    test_StringToPtr();
    test_EnsureNot_success();
    test_EnsureNot_failure();
    test_Ensure0_success();
    test_Ensure0_failure();
    test_CheckNull_Custom();

    std::cout << "All utils tests passed\n";
    return 0;
}
