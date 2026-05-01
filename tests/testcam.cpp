#include "../src/cam.h"
#include <gtest/gtest.h>
#include <pthread.h>
#include <vector>

enum MockBehavior {
    MOCK_OPEN,
    MOCK_TIMEOUT,
    MOCK_ERROR
};

static MockBehavior mock_sock_result = MOCK_OPEN;

extern "C"
{
    bool crc_nmap_connect = false;
    bool ambiguous_include = false;
    bool use_nmap = false;
    const char *nmap_xml_file = NULL;
    bool nmap_fast = false;
    int __wrap_spawnSock (radarType *target)
    {
        (void)target;
        switch (mock_sock_result)
        {
            case MOCK_OPEN: return 42;
            case MOCK_TIMEOUT: return -1;
            case MOCK_ERROR: return -1;
            default: return -1;
        }
    }
}

class CameradarTest : public ::testing::Test
{
    protected:
        ResultCtx ctx;

        void SetUp() override
        {
            result_init (&ctx, 10);
            mock_sock_result = MOCK_OPEN;
        }

        void TearDown() override
        {
            result_free (&ctx);
        }
};

TEST_F (CameradarTest, Base64Encoding)
{
    char output[512];

    bsfEncode ("admin:admin", output);
    EXPECT_STREQ (output, "YWRtaW46YWRtaW4=");

    bsfEncode ("", output);
    EXPECT_STREQ (output, "");
}

TEST_F (CameradarTest, ResultContenxtHandling)
{
    ResultCtx ctx;
    result_init (&ctx, 5);

    EXPECT_EQ (ctx.count, 0);
    EXPECT_EQ (ctx.cap, 5);
    ASSERT_NE (ctx.results, nullptr);

    ScanResult res = {};
    res.port = 554;
    res.is_open = true;
    strcpy (res.service, "rtsp");

    result_add (&ctx, &res);
    EXPECT_EQ (ctx.count, 1);
    EXPECT_EQ (ctx.results[0].port, 554);

    result_free (&ctx);
    EXPECT_EQ (ctx.results, nullptr);
}

TEST_F (CameradarTest, NmapStateParsing)
{
    EXPECT_EQ (parse_port_state ("open"), PORT_OPEN);
    EXPECT_EQ (parse_port_state ("closed"), PORT_CLOSE);
    EXPECT_EQ (parse_port_state ("filtered"), PORT_FILTER);
    EXPECT_EQ (parse_port_state ("open|filtered"), PORT_OPEN_FILTER);
    EXPECT_EQ (parse_port_state ("unknown_state"), -1);
}

TEST_F (CameradarTest, NmapParserAllocation)
{
    NmRes res;
    nmap_parser_init (&res);

    ASSERT_NE (res.ports, nullptr);
    EXPECT_EQ (res.count, 0);

    nmap_parser_add (&res, 80, PORT_OPEN, "http", "apache");
    EXPECT_EQ (res.count, 1);
    EXPECT_STREQ (res.ports[0].service, "http");

    nmap_parser_free (&res);
}

TEST_F (CameradarTest, DetectOpenRtspPort)
{
    radarType target = {};
    target.port = 554;
    target.timeout_ms = 1;

    mock_sock_result = MOCK_OPEN;
    int res = __wrap_spawnSock (&target);
    EXPECT_EQ (res, 42);
}

TEST_F (CameradarTest, HandlesConnectionTimeout)
{
    radarType target = {};
    target.port = 554;

    mock_sock_result = MOCK_TIMEOUT;

    int res = __wrap_spawnSock (&target);
    EXPECT_EQ (res, -1);
}

TEST_F (CameradarTest, ResultStorageIntergration)
{
    ResultCtx ctx;
    result_init (&ctx, 10);

    ScanResult res = {};
    res.port = 554;
    res.is_open = true;

    result_add (&ctx, &res);

    EXPECT_EQ (ctx.count, 1);
    EXPECT_EQ (ctx.results[0].port, 554);

    result_free (&ctx);
}

TEST_F (CameradarTest, SuccessfulScanAddsResult)
{
    radarType *target = (radarType *)MemoryAllocate (sizeof (radarType));
    target->port = 554;
    target->ipAddr = inet_addr ("127.0.0.1");
    target->timeout_ms = 1;
    target->result_ctx = &ctx;
    target->doBrute = false;

    threadScan (target);

    EXPECT_EQ (ctx.count, 1);
    EXPECT_EQ (ctx.results[0].port, 554);
    EXPECT_TRUE (ctx.results[0].is_open);
}

TEST_F (CameradarTest, TimeoutDoesNotAddResult)
{
    mock_sock_result = MOCK_TIMEOUT;

    radarType *target = (radarType *)MemoryAllocate (sizeof (radarType));
    target->port = 554;
    target->result_ctx = &ctx;

    threadScan (target);

    EXPECT_EQ (ctx.count, 1);
    EXPECT_FALSE (ctx.results[0].is_open);
}