// Unit tests for the netconn pure parser (ADR-0020) — fixture XML captured
// from a live Windows 11 box (wevtutil /f:xml, same rendering EvtRender
// produces), so the parser is pinned against real event shapes, not the docs.
// Cross-platform: tar_netconn.hpp is header-pure.

#include "tar_netconn.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

using yuzu::tar::format_event_systemtime;
using yuzu::tar::parse_event_systemtime;
using yuzu::tar::parse_netconn_event_xml;

namespace {

// Real NetworkProfile 10000 (network connected), captured 2026-07-03. The
// free-text fields (Name/Description/Guid) are exactly what must NEVER reach
// a row.
const std::string kNetProfileConnected = R"(<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-NetworkProfile' Guid='{fbcfac3f-8459-419f-8e48-1f0b49cdb85e}'/><EventID>10000</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000200000000020</Keywords><TimeCreated SystemTime='2026-07-03T13:35:23.8124269Z'/><EventRecordID>2408</EventRecordID><Correlation ActivityID='{c7cc53d1-0a32-0005-4254-ccc7320add01}'/><Execution ProcessID='2680' ThreadID='16684'/><Channel>Microsoft-Windows-NetworkProfile/Operational</Channel><Computer>DESKTOP-04DNSIG</Computer><Security UserID='S-1-5-20'/></System><EventData><Data Name='Name'>CorpHQ Secret Net</Data><Data Name='Description'>CorpHQ Secret Net</Data><Data Name='Guid'>{d4b44eeb-91e1-43f3-aa43-3871b88a3849}</Data><Data Name='Type'>0</Data><Data Name='State'>9</Data><Data Name='Category'>1</Data></EventData></Event>)";

// Real NCSI 4042 (capability change), captured 2026-07-03 on an
// internet-connected box: Capability=2 IS the internet state.
const std::string kNcsiCapability = R"(<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-NCSI' Guid='{314de49f-ce63-4779-ba2b-d616f6963a88}'/><EventID>4042</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000020</Keywords><TimeCreated SystemTime='2026-07-03T13:35:22.8666561Z'/><EventRecordID>333</EventRecordID><Correlation ActivityID='{c7cc53d1-0a32-0005-4254-ccc7320add01}'/><Execution ProcessID='2680' ThreadID='13720'/><Channel>Microsoft-Windows-NCSI/Operational</Channel><Computer>DESKTOP-04DNSIG</Computer><Security UserID='S-1-5-20'/></System><EventData><Data Name='InterfaceGuid'>{67f26f36-a70c-43bc-8bd4-bd5caaacab24}</Data><Data Name='IfLuid'>1689399716741120</Data><Data Name='Family'>0</Data><Data Name='Capability'>2</Data><Data Name='CapabilityChangeReason'>4</Data><Data Name='PreviousCapability'>0</Data></EventData></Event>)";

// WLAN-AutoConfig 8001 (Wi-Fi connect success), built from the shipped v0
// template's field list (this box is wired — no live sample): InterfaceGuid,
// InterfaceDescription, ConnectionMode, ProfileName, SSID, BSSType, PHYType,
// AuthenticationAlgorithm, CipherAlgorithm, OnexEnabled, ConnectionId,
// NonBroadcast. The SSID is the sentinel for the privacy test.
const std::string kWlanConnected = R"(<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WLAN-AutoConfig' Guid='{9580d7dd-0379-4658-9870-d5be7d52d6de}'/><EventID>8001</EventID><Version>0</Version><Level>4</Level><Task>24010</Task><Opcode>28000</Opcode><Keywords>0x8000000000000200</Keywords><TimeCreated SystemTime='2026-06-30T08:15:09.1234567Z'/><EventRecordID>99</EventRecordID><Channel>Microsoft-Windows-WLAN-AutoConfig/Operational</Channel><Computer>LAPTOP-XYZ</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='InterfaceGuid'>{11111111-2222-3333-4444-555555555555}</Data><Data Name='InterfaceDescription'>Intel(R) Wi-Fi 6E AX211</Data><Data Name='ConnectionMode'>Connection to a secure network without a profile</Data><Data Name='ProfileName'>CorpHQ-WPA3</Data><Data Name='SSID'>CorpHQ Secret WiFi</Data><Data Name='BSSType'>Infrastructure</Data><Data Name='PHYType'>802.11ax</Data><Data Name='AuthenticationAlgorithm'>WPA3-SAE</Data><Data Name='CipherAlgorithm'>AES-GCMP-256</Data><Data Name='OnexEnabled'>0</Data><Data Name='ConnectionId'>0x1a2b3c4d</Data><Data Name='NonBroadcast'>false</Data></EventData></Event>)";

// WLAN-AutoConfig 8003 (Wi-Fi disconnect) with a reason code.
const std::string kWlanDisconnected = R"(<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WLAN-AutoConfig' Guid='{9580d7dd-0379-4658-9870-d5be7d52d6de}'/><EventID>8003</EventID><Version>0</Version><Level>4</Level><TimeCreated SystemTime='2026-06-30T17:44:01.0000000Z'/><EventRecordID>101</EventRecordID><Channel>Microsoft-Windows-WLAN-AutoConfig/Operational</Channel><Computer>LAPTOP-XYZ</Computer></System><EventData><Data Name='InterfaceGuid'>{11111111-2222-3333-4444-555555555555}</Data><Data Name='InterfaceDescription'>Intel(R) Wi-Fi 6E AX211</Data><Data Name='ConnectionMode'>Automatic connection with a profile</Data><Data Name='ProfileName'>CorpHQ-WPA3</Data><Data Name='SSID'>CorpHQ Secret WiFi</Data><Data Name='BSSType'>Infrastructure</Data><Data Name='Reason'>The network is disconnected by the driver</Data><Data Name='ReasonCode'>229377</Data></EventData></Event>)";

} // namespace

TEST_CASE("netconn: SystemTime parses to epoch and round-trips the XPath format",
          "[tar][netconn]") {
    // 2026-07-03T13:35:23Z == 1783085723 (fraction truncated).
    CHECK(parse_event_systemtime("2026-07-03T13:35:23.8124269Z") == 1783085723);
    CHECK(parse_event_systemtime("1970-01-01T00:00:01.000Z") == 1);

    // Round-trip: format -> parse is identity on whole seconds (the reader
    // builds its XPath window with format_event_systemtime).
    for (const std::int64_t ts : {1783085723LL, 0LL, 946684800LL}) {
        CHECK(parse_event_systemtime(format_event_systemtime(ts)) == ts);
    }

    // Malformed shapes -> 0 (dropped by every window check).
    CHECK(parse_event_systemtime("") == 0);
    CHECK(parse_event_systemtime("2026-07-03") == 0);
    CHECK(parse_event_systemtime("garbage-time-string") == 0);
    CHECK(parse_event_systemtime("1969-12-31T23:59:59Z") == 0); // pre-epoch
}

TEST_CASE("netconn: NetworkProfile 10000/10001 map to connected/disconnected + category",
          "[tar][netconn]") {
    auto row = parse_netconn_event_xml("networkprofile", kNetProfileConnected);
    REQUIRE(row.has_value());
    CHECK(row->ts == 1783085723);
    CHECK(row->action == "connected");
    CHECK(row->channel == "networkprofile");
    CHECK(row->category == "private"); // Category=1
    CHECK(row->capability.empty());
    CHECK(row->iface_kind.empty());
    CHECK(row->reason_code == 0);

    // Same payload as a 10001 -> disconnected.
    std::string disc = kNetProfileConnected;
    const auto pos = disc.find("<EventID>10000</EventID>");
    REQUIRE(pos != std::string::npos);
    disc.replace(pos, 24, "<EventID>10001</EventID>");
    auto drow = parse_netconn_event_xml("networkprofile", disc);
    REQUIRE(drow.has_value());
    CHECK(drow->action == "disconnected");

    // An ID outside the channel's mapping is rejected, not misfiled.
    CHECK_FALSE(parse_netconn_event_xml("networkprofile", kNcsiCapability).has_value());
}

TEST_CASE("netconn: NCSI 4042 maps to capability_changed with capability + reason",
          "[tar][netconn]") {
    auto row = parse_netconn_event_xml("ncsi", kNcsiCapability);
    REQUIRE(row.has_value());
    CHECK(row->action == "capability_changed");
    CHECK(row->channel == "ncsi");
    CHECK(row->capability == "internet"); // Capability=2, pinned from live capture
    CHECK(row->reason_code == 4);         // CapabilityChangeReason
    CHECK(row->category.empty());
}

TEST_CASE("netconn: WLAN 8001/8003 map to wifi actions with reason code",
          "[tar][netconn]") {
    auto con = parse_netconn_event_xml("wlan", kWlanConnected);
    REQUIRE(con.has_value());
    CHECK(con->action == "wifi_connected");
    CHECK(con->channel == "wlan");
    CHECK(con->iface_kind == "wifi");
    CHECK(con->reason_code == 0); // no ReasonCode on a success event

    auto dis = parse_netconn_event_xml("wlan", kWlanDisconnected);
    REQUIRE(dis.has_value());
    CHECK(dis->action == "wifi_disconnected");
    CHECK(dis->reason_code == 229377);
}

TEST_CASE("netconn: PRIVACY — no free-text event field ever reaches a row",
          "[tar][netconn][privacy]") {
    // The fixtures deliberately carry sentinel secrets: an SSID, a profile
    // name, network Name/Description, interface GUIDs/descriptions. Serialize
    // every parsed row field and assert none of it leaked. This is the
    // allow-list contract of parse_netconn_event_xml — a parser change that
    // starts copying free-text fields must fail HERE.
    const std::string sentinels[] = {
        "Secret",          // SSID "CorpHQ Secret WiFi" / Name "CorpHQ Secret Net"
        "CorpHQ",          // profile name / SSID / network name fragments
        "Intel",           // InterfaceDescription
        "67f26f36",        // NCSI InterfaceGuid fragment
        "11111111",        // WLAN InterfaceGuid fragment
        "d4b44eeb",        // NetworkProfile network Guid fragment
        "DESKTOP-04DNSIG", // Computer
        "LAPTOP-XYZ",
    };
    const struct {
        const char* channel;
        const std::string* xml;
    } cases[] = {
        {"networkprofile", &kNetProfileConnected},
        {"ncsi", &kNcsiCapability},
        {"wlan", &kWlanConnected},
        {"wlan", &kWlanDisconnected},
    };
    for (const auto& c : cases) {
        auto row = parse_netconn_event_xml(c.channel, *c.xml);
        REQUIRE(row.has_value());
        const std::string flat = row->action + "|" + row->channel + "|" + row->category +
                                 "|" + row->capability + "|" + row->iface_kind + "|" +
                                 std::to_string(row->reason_code) + "|" +
                                 std::to_string(row->ts) + "|" +
                                 std::to_string(row->snapshot_id);
        for (const auto& s : sentinels) {
            INFO("channel=" << c.channel << " sentinel=" << s << " row=" << flat);
            CHECK(flat.find(s) == std::string::npos);
        }
    }
}

TEST_CASE("netconn: unknown channel tag or missing timestamp is rejected", "[tar][netconn]") {
    CHECK_FALSE(parse_netconn_event_xml("journal", kNetProfileConnected).has_value());
    CHECK_FALSE(parse_netconn_event_xml("", kNetProfileConnected).has_value());
    // No TimeCreated -> ts 0 -> rejected before any field extraction.
    CHECK_FALSE(parse_netconn_event_xml(
                    "networkprofile",
                    "<Event><System><EventID>10000</EventID></System></Event>")
                    .has_value());
}

// ── Real-host reader behaviour (pattern: test_tar_proc_etw.cpp — the platform
// reader compiles everywhere; Windows runs it against the live OS, elsewhere
// its no-op contract is pinned). Event COUNTS are host-dependent, so the
// assertions pin the reader's invariants, not the host's history.

TEST_CASE("netconn: backfill_netconn_events honours the window and the closed enums",
          "[tar][netconn]") {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
#ifdef _WIN32
    // Live read of the real OS channels over the last 7 days. Whatever comes
    // back must respect the window, the closed enum sets, and the privacy
    // shape (enum tokens never look like SSIDs/GUIDs/addresses).
    const auto rows = yuzu::tar::backfill_netconn_events(now - 7 * 24 * 3600, now);
    for (const auto& r : rows) {
        INFO("action=" << r.action << " channel=" << r.channel << " ts=" << r.ts);
        CHECK(r.ts >= now - 7 * 24 * 3600);
        CHECK(r.ts < now);
        CHECK((r.channel == "networkprofile" || r.channel == "ncsi" || r.channel == "wlan"));
        CHECK((r.action == "connected" || r.action == "disconnected" ||
               r.action == "wifi_connected" || r.action == "wifi_connect_failed" ||
               r.action == "wifi_disconnected" || r.action == "capability_changed"));
        CHECK((r.category.empty() || r.category == "public" || r.category == "private" ||
               r.category == "domain"));
        CHECK((r.capability.empty() || r.capability == "none" || r.capability == "local" ||
               r.capability == "internet"));
        CHECK((r.iface_kind.empty() || r.iface_kind == "wifi"));
    }
    // Inverted / empty windows are a guaranteed no-op.
    CHECK(yuzu::tar::backfill_netconn_events(now, now - 60).empty());
    CHECK(yuzu::tar::backfill_netconn_events(now - 60, now, /*cap=*/0).empty());
#else
    // Clean no-op off Windows (journald/oslog readers are kPlanned).
    CHECK(yuzu::tar::backfill_netconn_events(now - 7 * 24 * 3600, now).empty());
#endif
}
