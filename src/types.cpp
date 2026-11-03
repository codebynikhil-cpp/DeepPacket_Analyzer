#include "types.h"
#include "platform.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <initializer_list>

namespace DPI {

static bool isDomainOrSubdomain(const std::string& hostname,
                                std::initializer_list<const char*> domains) {
    for (const char* domain : domains) {
        const std::string suffix(domain);
        if (hostname == suffix ||
            (hostname.size() > suffix.size() &&
             hostname.compare(hostname.size() - suffix.size(), suffix.size(), suffix) == 0 &&
             hostname[hostname.size() - suffix.size() - 1] == '.')) return true;
    }
    return false;
}

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    ss << src_ip << ":" << src_port
       << " -> "
       << dst_ip << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:       return "Unknown";
        case AppType::HTTP:          return "HTTP";
        case AppType::HTTPS:         return "HTTPS";
        case AppType::DNS:           return "DNS";
        case AppType::TLS:           return "TLS";
        case AppType::QUIC:          return "QUIC";
        
        // Search & Big Tech
        case AppType::GOOGLE:        return "Google";
        case AppType::MICROSOFT:     return "Microsoft";
        case AppType::APPLE:         return "Apple";
        case AppType::AMAZON:        return "Amazon";
        case AppType::CLOUDFLARE:    return "Cloudflare";
        
        // Social & Messaging
        case AppType::FACEBOOK:      return "Facebook";
        case AppType::INSTAGRAM:     return "Instagram";
        case AppType::WHATSAPP:      return "WhatsApp";
        case AppType::TWITTER:       return "Twitter/X";
        case AppType::TELEGRAM:      return "Telegram";
        case AppType::TIKTOK:        return "TikTok";
        case AppType::DISCORD:       return "Discord";
        case AppType::REDDIT:        return "Reddit";
        case AppType::LINKEDIN:      return "LinkedIn";
        case AppType::SNAPCHAT:      return "Snapchat";
        case AppType::PINTEREST:     return "Pinterest";
        
        // Video & Streaming & Media
        case AppType::YOUTUBE:       return "YouTube";
        case AppType::NETFLIX:       return "Netflix";
        case AppType::SPOTIFY:       return "Spotify";
        case AppType::TWITCH:        return "Twitch";
        case AppType::DISNEYPLUS:    return "Disney+";
        case AppType::HULU:          return "Hulu";
        case AppType::SOUNDCLOUD:    return "SoundCloud";
        
        // AI, Productivity & Collaboration
        case AppType::OPENAI:        return "ChatGPT/OpenAI";
        case AppType::NOTION:        return "Notion";
        case AppType::ZOOM:          return "Zoom";
        case AppType::SLACK:         return "Slack";
        case AppType::TEAMS:         return "Microsoft Teams";
        case AppType::CANVA:         return "Canva";
        case AppType::FIGMA:         return "Figma";
        case AppType::TRELLO:        return "Trello";
        
        // Developer & Tech / Learning
        case AppType::GITHUB:        return "GitHub";
        case AppType::GITLAB:        return "GitLab";
        case AppType::BITBUCKET:     return "Bitbucket";
        case AppType::STACKOVERFLOW: return "StackOverflow";
        case AppType::LEETCODE:      return "LeetCode";
        case AppType::WIKIPEDIA:     return "Wikipedia";
        case AppType::COURSERA:      return "Coursera";
        case AppType::MEDIUM:        return "Medium";

        case AppType::NPM:           return "npm Registry";
        case AppType::DOCKER:        return "Docker";
        case AppType::HUGGINGFACE:   return "Hugging Face";
        case AppType::KAGGLE:        return "Kaggle";
        case AppType::GEEKSFORGEEKS: return "GeeksforGeeks";
        case AppType::CODECHEF:      return "CodeChef";
        case AppType::HACKERRANK:    return "HackerRank";
        
        // Gaming & Entertainment
        case AppType::STEAM:         return "Steam";
        case AppType::ROBLOX:        return "Roblox";
        case AppType::EPICGAMES:     return "Epic Games";
        case AppType::RIOTGAMES:     return "Riot Games";
        
        // E-Commerce & Services
        case AppType::EBAY:          return "eBay";
        case AppType::ALIEXPRESS:    return "AliExpress";
        case AppType::PAYPAL:        return "PayPal";
        case AppType::UBER:          return "Uber";
        
        default:                     return "Unknown";
    }
}

// Map SNI/domain to application type
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    // Convert to lowercase for matching
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    // Check for known patterns
    
    // ── YouTube (Checked before general Google to capture googlevideo/yt3.ggpht) ──
    if (lower_sni.find("youtube") != std::string::npos ||
        lower_sni.find("googlevideo") != std::string::npos ||
        lower_sni.find("ytimg") != std::string::npos ||
        isDomainOrSubdomain(lower_sni, {"youtu.be"}) ||
        lower_sni.find("yt3.ggpht") != std::string::npos) {
        return AppType::YOUTUBE;
    }
    
    // ── Google ──
    if (lower_sni.find("google") != std::string::npos ||
        lower_sni.find("gstatic") != std::string::npos ||
        lower_sni.find("googleapis") != std::string::npos ||
        lower_sni.find("ggpht") != std::string::npos ||
        lower_sni.find("gvt1") != std::string::npos ||
        lower_sni.find("1e100.net") != std::string::npos) {
        return AppType::GOOGLE;
    }
    
    // ── Facebook/Meta ──
    if (lower_sni.find("facebook") != std::string::npos ||
        lower_sni.find("fbcdn") != std::string::npos ||
        isDomainOrSubdomain(lower_sni, {"fb.com"}) ||
        lower_sni.find("fbsbx") != std::string::npos ||
        isDomainOrSubdomain(lower_sni, {"meta.com"})) {
        return AppType::FACEBOOK;
    }
    
    // ── Instagram ──
    if (lower_sni.find("instagram") != std::string::npos ||
        lower_sni.find("cdninstagram") != std::string::npos) {
        return AppType::INSTAGRAM;
    }
    
    // ── WhatsApp ──
    if (lower_sni.find("whatsapp") != std::string::npos ||
        isDomainOrSubdomain(lower_sni, {"wa.me"})) {
        return AppType::WHATSAPP;
    }
    
    // ── Twitter/X ──
    if (lower_sni.find("twitter") != std::string::npos ||
        lower_sni.find("twimg") != std::string::npos ||
        isDomainOrSubdomain(lower_sni, {"x.com", "t.co"})) {
        return AppType::TWITTER;
    }
    
    // ── Snapchat ──
    if (lower_sni.find("snapchat") != std::string::npos ||
        lower_sni.find("sc-cdn") != std::string::npos) {
        return AppType::SNAPCHAT;
    }
    
    // ── Pinterest ──
    if (lower_sni.find("pinterest") != std::string::npos ||
        lower_sni.find("pinimg") != std::string::npos) {
        return AppType::PINTEREST;
    }
    
    // ── Netflix ──
    if (lower_sni.find("netflix") != std::string::npos ||
        lower_sni.find("nflxvideo") != std::string::npos ||
        lower_sni.find("nflximg") != std::string::npos ||
        lower_sni.find("nflxext") != std::string::npos) {
        return AppType::NETFLIX;
    }
    
    // ── Disney+ & Hulu ──
    if (lower_sni.find("disneyplus") != std::string::npos ||
        lower_sni.find("bamgrid") != std::string::npos) {
        return AppType::DISNEYPLUS;
    }
    if (lower_sni.find("hulu") != std::string::npos) {
        return AppType::HULU;
    }
    
    // ── Amazon & AWS ──
    if (lower_sni.find("amazon") != std::string::npos ||
        lower_sni.find("amazonaws") != std::string::npos ||
        lower_sni.find("cloudfront") != std::string::npos ||
        lower_sni.find("aws") != std::string::npos ||
        lower_sni.find("media-amazon") != std::string::npos) {
        return AppType::AMAZON;
    }
    
    // ── Microsoft Teams (check before general Microsoft) ──
    if (isDomainOrSubdomain(lower_sni, {"teams.microsoft.com", "teams.live.com"})) {
        return AppType::TEAMS;
    }
    
    // ── Microsoft ──
    if (lower_sni.find("microsoft") != std::string::npos ||
        isDomainOrSubdomain(lower_sni, {"msn.com"}) ||
        lower_sni.find("office") != std::string::npos ||
        lower_sni.find("azure") != std::string::npos ||
        isDomainOrSubdomain(lower_sni, {"live.com"}) ||
        lower_sni.find("outlook") != std::string::npos ||
        lower_sni.find("bing") != std::string::npos ||
        lower_sni.find("windows") != std::string::npos) {
        return AppType::MICROSOFT;
    }
    
    // ── Apple ──
    if (lower_sni.find("apple") != std::string::npos ||
        lower_sni.find("icloud") != std::string::npos ||
        lower_sni.find("mzstatic") != std::string::npos ||
        lower_sni.find("itunes") != std::string::npos ||
        lower_sni.find("aaplimg") != std::string::npos) {
        return AppType::APPLE;
    }
    
    // ── Telegram ──
    if (lower_sni.find("telegram") != std::string::npos ||
        isDomainOrSubdomain(lower_sni, {"t.me"})) {
        return AppType::TELEGRAM;
    }
    
    // ── TikTok ──
    if (lower_sni.find("tiktok") != std::string::npos ||
        lower_sni.find("tiktokcdn") != std::string::npos ||
        lower_sni.find("musical.ly") != std::string::npos ||
        lower_sni.find("bytedance") != std::string::npos ||
        lower_sni.find("byteoversea") != std::string::npos) {
        return AppType::TIKTOK;
    }
    
    // ── Spotify ──
    if (lower_sni.find("spotify") != std::string::npos ||
        isDomainOrSubdomain(lower_sni, {"scdn.co", "spoti.fi"})) {
        return AppType::SPOTIFY;
    }
    
    // ── Twitch ──
    if (lower_sni.find("twitch") != std::string::npos ||
        lower_sni.find("ttvnw.net") != std::string::npos ||
        lower_sni.find("jtvnw.net") != std::string::npos) {
        return AppType::TWITCH;
    }
    
    // ── SoundCloud ──
    if (lower_sni.find("soundcloud") != std::string::npos ||
        lower_sni.find("sndcdn") != std::string::npos) {
        return AppType::SOUNDCLOUD;
    }
    
    // ── Zoom ──
    if (isDomainOrSubdomain(lower_sni, {"zoom.us"}) ||
        lower_sni.find("zoomgov") != std::string::npos ||
        lower_sni.find("zoom") != std::string::npos) {
        return AppType::ZOOM;
    }
    
    // ── Slack ──
    if (lower_sni.find("slack") != std::string::npos ||
        lower_sni.find("slack-edge") != std::string::npos ||
        lower_sni.find("slack-msgs") != std::string::npos) {
        return AppType::SLACK;
    }
    
    // ── Discord ──
    if (lower_sni.find("discord") != std::string::npos ||
        lower_sni.find("discordapp") != std::string::npos ||
        lower_sni.find("discordstatus") != std::string::npos) {
        return AppType::DISCORD;
    }
    
    // ── GitHub ──
    if (lower_sni.find("github") != std::string::npos ||
        lower_sni.find("githubusercontent") != std::string::npos ||
        lower_sni.find("github.io") != std::string::npos ||
        isDomainOrSubdomain(lower_sni, {"ghcr.io"})) {
        return AppType::GITHUB;
    }
    
    // ── GitLab ──
    if (lower_sni.find("gitlab") != std::string::npos) {
        return AppType::GITLAB;
    }
    
    // ── Bitbucket ──
    if (lower_sni.find("bitbucket") != std::string::npos) {
        return AppType::BITBUCKET;
    }
    
    // ── Cloudflare ──
    if (lower_sni.find("cloudflare") != std::string::npos ||
        lower_sni.find("cf-") != std::string::npos ||
        lower_sni.find("cdnjs") != std::string::npos) {
        return AppType::CLOUDFLARE;
    }
    
    // ── Wikipedia / Wikimedia ──
    if (lower_sni.find("wikipedia") != std::string::npos ||
        lower_sni.find("wikimedia") != std::string::npos ||
        lower_sni.find("wikidata") != std::string::npos) {
        return AppType::WIKIPEDIA;
    }
    
    // ── Coursera ──
    if (lower_sni.find("coursera") != std::string::npos) {
        return AppType::COURSERA;
    }

    
    // ── Reddit ──
    if (lower_sni.find("reddit") != std::string::npos ||
        isDomainOrSubdomain(lower_sni, {"redd.it"}) ||
        lower_sni.find("redditmedia") != std::string::npos) {
        return AppType::REDDIT;
    }
    
    // ── OpenAI / ChatGPT ──
    if (lower_sni.find("openai") != std::string::npos ||
        lower_sni.find("chatgpt") != std::string::npos ||
        lower_sni.find("oaistatic") != std::string::npos ||
        lower_sni.find("oaiusercontent") != std::string::npos) {
        return AppType::OPENAI;
    }
    
    // ── Notion ──
    if (lower_sni.find("notion") != std::string::npos ||
        lower_sni.find("notion.so") != std::string::npos ||
        lower_sni.find("notion.site") != std::string::npos) {
        return AppType::NOTION;
    }
    
    // ── Canva / Figma / Trello ──
    if (lower_sni.find("canva") != std::string::npos) {
        return AppType::CANVA;
    }
    if (lower_sni.find("figma") != std::string::npos) {
        return AppType::FIGMA;
    }
    if (lower_sni.find("trello") != std::string::npos) {
        return AppType::TRELLO;
    }
    
    // ── LeetCode ──
    if (lower_sni.find("leetcode") != std::string::npos) {
        return AppType::LEETCODE;
    }
    
    // ── GeeksforGeeks / CodeChef / HackerRank ──
    if (lower_sni.find("geeksforgeeks") != std::string::npos ||
        lower_sni.find("gfg") != std::string::npos) {
        return AppType::GEEKSFORGEEKS;
    }
    if (lower_sni.find("codechef") != std::string::npos) {
        return AppType::CODECHEF;
    }
    if (lower_sni.find("hackerrank") != std::string::npos) {
        return AppType::HACKERRANK;
    }
    
    // ── LinkedIn ──
    if (lower_sni.find("linkedin") != std::string::npos ||
        lower_sni.find("licdn") != std::string::npos) {
        return AppType::LINKEDIN;
    }
    
    // ── StackOverflow ──
    if (lower_sni.find("stackoverflow") != std::string::npos ||
        lower_sni.find("stackexchange") != std::string::npos ||
        lower_sni.find("sstatic.net") != std::string::npos) {
        return AppType::STACKOVERFLOW;
    }
    
    // ── Medium ──
    if (isDomainOrSubdomain(lower_sni, {"medium.com"})) {
        return AppType::MEDIUM;
    }
    
    // ── NPM & Docker ──
    if (lower_sni.find("npmjs") != std::string::npos ||
        lower_sni.find("npmjs.org") != std::string::npos) {
        return AppType::NPM;
    }
    if (lower_sni.find("docker") != std::string::npos ||
        lower_sni.find("dockerhub") != std::string::npos) {
        return AppType::DOCKER;
    }
    
    // ── Hugging Face & Kaggle (AI / Data Science) ──
    if (lower_sni.find("huggingface") != std::string::npos ||
        isDomainOrSubdomain(lower_sni, {"hf.co"})) {
        return AppType::HUGGINGFACE;
    }
    if (lower_sni.find("kaggle") != std::string::npos) {
        return AppType::KAGGLE;
    }
    
    // ── Gaming (Steam, Roblox, Epic Games, Riot Games) ──
    if (lower_sni.find("steampowered") != std::string::npos ||
        lower_sni.find("steamcommunity") != std::string::npos ||
        lower_sni.find("steamstatic") != std::string::npos ||
        lower_sni.find("valvesoftware") != std::string::npos) {
        return AppType::STEAM;
    }
    if (lower_sni.find("roblox") != std::string::npos ||
        lower_sni.find("rbxcdn") != std::string::npos) {
        return AppType::ROBLOX;
    }
    if (lower_sni.find("epicgames") != std::string::npos ||
        lower_sni.find("unrealengine") != std::string::npos) {
        return AppType::EPICGAMES;
    }
    if (lower_sni.find("riotgames") != std::string::npos ||
        lower_sni.find("leagueoflegends") != std::string::npos ||
        lower_sni.find("valortant") != std::string::npos ||
        lower_sni.find("valorant") != std::string::npos) {
        return AppType::RIOTGAMES;
    }
    
    // ── E-Commerce & FinTech (eBay, AliExpress, PayPal, Uber) ──
    if (lower_sni.find("ebay") != std::string::npos) {
        return AppType::EBAY;
    }
    if (lower_sni.find("aliexpress") != std::string::npos ||
        lower_sni.find("alibaba") != std::string::npos) {
        return AppType::ALIEXPRESS;
    }
    if (lower_sni.find("paypal") != std::string::npos) {
        return AppType::PAYPAL;
    }
    if (lower_sni.find("uber") != std::string::npos) {
        return AppType::UBER;
    }
    
    // If SNI is present but not recognized, still mark as TLS/HTTPS
    return AppType::HTTPS;
}


// ---------------------------------------------------------------------------
// IP-range to application mapping
// Covers services that use direct IP connections (MTProto, QUIC-direct, etc.)
// IP ranges are stored in network byte order (big-endian) as received by the
// packet parser (src_ip_num / dest_ip_num).
// ---------------------------------------------------------------------------
static bool inRange(uint32_t ip, uint32_t net_be, uint8_t prefix) {
    // ip and net_be are both in network byte order; convert to host order for arithmetic
    const uint32_t ip_h  = PortableNet::netToHost32(ip);
    const uint32_t net_h = PortableNet::netToHost32(net_be);
    if (prefix == 0) return true;
    const uint32_t mask = prefix >= 32 ? 0xFFFFFFFFu : ~((1u << (32 - prefix)) - 1);
    return (ip_h & mask) == (net_h & mask);
}

// Helper: build a uint32_t in network-byte-order from dotted-decimal octets
static constexpr uint32_t IP4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (static_cast<uint32_t>(a) << 24) |
           (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(c) <<  8) |
            static_cast<uint32_t>(d);
}

AppType ipToAppType(uint32_t ip_be) {
    // Convert from network byte order to host order for matching
    const uint32_t ip = PortableNet::netToHost32(ip_be);

    // Helper lambda
    auto inR = [&](uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t prefix) -> bool {
        const uint32_t net = IP4(a, b, c, d);
        if (prefix == 0) return true;
        const uint32_t mask = prefix >= 32 ? 0xFFFFFFFFu : ~((1u << (32 - prefix)) - 1u);
        return (ip & mask) == (net & mask);
    };

    // ── Telegram (MTProto servers) ──────────────────────────────────────────
    // Official Telegram IP ranges: https://core.telegram.org/resources/cidr.txt
    if (inR(91,108,4,0,   22) || // 91.108.4.0/22
        inR(91,108,8,0,   22) || // 91.108.8.0/22
        inR(91,108,12,0,  22) || // 91.108.12.0/22
        inR(91,108,16,0,  22) || // 91.108.16.0/22
        inR(91,108,20,0,  22) || // 91.108.20.0/22
        inR(91,108,56,0,  22) || // 91.108.56.0/22 (media/CDN)
        inR(91,108,60,0,  22) || // 91.108.60.0/22
        inR(149,154,160,0,20) || // 149.154.160.0/20
        inR(2,21,231,0,  24) ||  // 2.21.231.0/24
        inR(2,22,50,0,   24))    // 2.22.50.0/24
        return AppType::TELEGRAM;

    // ── WhatsApp / Meta ─────────────────────────────────────────────────────
    // Meta/Facebook ASN 32934 commonly used ranges
    if (inR(31,13,24,0,  21) ||  // 31.13.24.0/21
        inR(31,13,64,0,  18) ||  // 31.13.64.0/18
        inR(66,220,144,0,20) ||  // 66.220.144.0/20
        inR(69,63,176,0, 20) ||  // 69.63.176.0/20
        inR(69,171,224,0,19) ||  // 69.171.224.0/19
        inR(74,119,76,0, 22) ||  // 74.119.76.0/22
        inR(102,132,96,0,20) ||  // 102.132.96.0/20
        inR(157,240,0,0, 16) ||  // 157.240.0.0/16
        inR(173,252,64,0,18) ||  // 173.252.64.0/18
        inR(204,15,20,0, 22))    // 204.15.20.0/22
        return AppType::FACEBOOK;

    // ── Google ──────────────────────────────────────────────────────────────
    if (inR(8,8,8,0,    24) ||   // 8.8.8.0/24   (DNS)
        inR(8,8,4,0,    24) ||   // 8.8.4.0/24   (DNS)
        inR(142,250,0,0, 15) ||  // 142.250.0.0/15
        inR(142,251,0,0, 16) ||  // 142.251.0.0/16
        inR(172,217,0,0, 16) ||  // 172.217.0.0/16
        inR(173,194,0,0, 16) ||  // 173.194.0.0/16
        inR(216,58,192,0,19) ||  // 216.58.192.0/19
        inR(74,125,0,0,  16))    // 74.125.0.0/16
        return AppType::GOOGLE;

    // ── Cloudflare ──────────────────────────────────────────────────────────
    if (inR(1,1,1,0,    24) ||   // 1.1.1.0/24   (DNS)
        inR(1,0,0,0,    24) ||   // 1.0.0.0/24
        inR(103,21,244,0,22) ||  // 103.21.244.0/22
        inR(103,22,200,0,22) ||  // 103.22.200.0/22
        inR(103,31,4,0, 22) ||   // 103.31.4.0/22
        inR(104,16,0,0,  13) ||  // 104.16.0.0/13
        inR(104,24,0,0,  14) ||  // 104.24.0.0/14
        inR(108,162,192,0,18) || // 108.162.192.0/18
        inR(162,158,0,0, 15) ||  // 162.158.0.0/15
        inR(172,64,0,0,  13) ||  // 172.64.0.0/13
        inR(173,245,48,0,20) ||  // 173.245.48.0/20
        inR(188,114,96,0,20) ||  // 188.114.96.0/20
        inR(190,93,240,0,20) ||  // 190.93.240.0/20
        inR(197,234,240,0,22) || // 197.234.240.0/22
        inR(198,41,128,0,17))    // 198.41.128.0/17
        return AppType::CLOUDFLARE;

    // ── Amazon / AWS ─────────────────────────────────────────────────────────
    if (inR(52,0,0,0,   11) ||   // 52.0.0.0/11  (large AWS block)
        inR(54,0,0,0,   11) ||   // 54.0.0.0/11
        inR(18,0,0,0,   11) ||   // 18.0.0.0/11
        inR(3,0,0,0,    11) ||   // 3.0.0.0/11
        inR(13,32,0,0,  15) ||   // 13.32.0.0/15 (CloudFront)
        inR(205,251,192,0,19))   // 205.251.192.0/19 (Route53/CF)
        return AppType::AMAZON;

    // ── Microsoft / Azure ───────────────────────────────────────────────────
    if (inR(13,64,0,0,  11) ||   // 13.64.0.0/11
        inR(20,0,0,0,    8) ||   // 20.0.0.0/8  (huge Azure block)
        inR(40,64,0,0,  10) ||   // 40.64.0.0/10
        inR(52,224,0,0,  11) ||  // 52.224.0.0/11
        inR(104,40,0,0,  13))    // 104.40.0.0/13
        return AppType::MICROSOFT;

    // ── Apple / iCloud ──────────────────────────────────────────────────────
    if (inR(17,0,0,0,    8))     // 17.0.0.0/8 (Apple owns entire /8)
        return AppType::APPLE;

    return AppType::UNKNOWN;
}
} // namespace DPI
