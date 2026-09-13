use sanalu::intelligence::{BotCategory, UserAgentClassifier};

#[test]
fn test_bot_category_conversions() {
    assert_eq!(BotCategory::SecurityTesting.as_str(), "security_testing");
    assert_eq!(
        BotCategory::from_str_name("scanners"),
        Some(BotCategory::SecurityTesting)
    );
    assert_eq!(
        BotCategory::from_str_name("ai_crawler"),
        Some(BotCategory::AiCrawler)
    );
    assert_eq!(BotCategory::from_str_name("unknown_cat"), None);

    assert_eq!(BotCategory::Empty.as_str(), "empty");
    assert_eq!(
        BotCategory::from_str_name("empty"),
        Some(BotCategory::Empty)
    );
    assert_eq!(
        BotCategory::from_str_name("missing"),
        Some(BotCategory::Empty)
    );

    assert!(BotCategory::SecurityTesting.is_blocked_by_default());
    assert!(!BotCategory::AiCrawler.is_blocked_by_default());
    assert!(BotCategory::BadScraper.is_blocked_by_default());
    assert!(BotCategory::GenericTools.is_blocked_by_default());
    assert!(BotCategory::Empty.is_blocked_by_default());
    assert!(!BotCategory::Search.is_blocked_by_default());
    assert!(!BotCategory::Monitoring.is_blocked_by_default());
}

#[test]
fn test_user_agent_classification() {
    let classifier = UserAgentClassifier::new();

    assert_eq!(
        classifier.classify("zgrab/0.x (compatible; Research)"),
        BotCategory::SecurityTesting
    );
    assert_eq!(
        classifier.classify("sqlmap/1.5.2#stable"),
        BotCategory::SecurityTesting
    );
    assert_eq!(
        classifier.classify("Mozilla/5.0 (compatible; CensysInspect/1.1)"),
        BotCategory::SecurityTesting
    );

    assert_eq!(
        classifier
            .classify("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0)"),
        BotCategory::AiCrawler
    );
    assert_eq!(
        classifier.classify("Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)"),
        BotCategory::AiCrawler
    );
    assert_eq!(
        classifier.classify("CCBot/2.0 (https://commoncrawl.org/faq/)"),
        BotCategory::AiCrawler
    );

    assert_eq!(
        classifier
            .classify("Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)"),
        BotCategory::BadScraper
    );
    assert_eq!(
        classifier.classify("SEOkicks-Robot"),
        BotCategory::BadScraper
    );

    assert_eq!(
        classifier.classify("curl/7.81.0"),
        BotCategory::GenericTools
    );
    assert_eq!(
        classifier.classify("python-requests/2.28.1"),
        BotCategory::GenericTools
    );
    assert_eq!(
        classifier.classify("Go-http-client/1.1"),
        BotCategory::GenericTools
    );
    assert_eq!(classifier.classify("-"), BotCategory::Empty);
    assert_eq!(classifier.classify(""), BotCategory::Empty);
    assert_eq!(classifier.classify("   "), BotCategory::Empty);

    assert_eq!(
        classifier
            .classify("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
        BotCategory::Search
    );
    assert_eq!(
        classifier
            .classify("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
        BotCategory::Search
    );

    assert_eq!(
        classifier.classify("Twitterbot/1.0"),
        BotCategory::SocialPreview
    );
    assert_eq!(
        classifier
            .classify("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"),
        BotCategory::SocialPreview
    );

    assert_eq!(
        classifier.classify("Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)"),
        BotCategory::Monitoring
    );

    assert_eq!(
        classifier.classify("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        BotCategory::BrowserOrUnknown
    );
}

#[test]
fn test_reference_scanners_classification() {
    let classifier = UserAgentClassifier::new();

    let security_scanners = [
        "wp2shell",
        "r00ts3c",
        "vitesweep",
        "metabase-cve",
        "l9explore",
        "l9tcpid",
        "zmap",
        "rawgrab",
        "cgrab",
        "masscan-ng",
        "wanscanner",
        "siteradar",
        "rootevidence",
        "qmx-internet",
        "net-research",
        "ai-exposure",
        "host-probe",
        "fhms-its",
        "ffuf",
        "feroxbuster",
        "wfuzz",
        "wpscan",
        "commix",
        "dsss",
        "mozlila",
        "mozila/",
    ];

    for ua in security_scanners {
        assert_eq!(
            classifier.classify(ua),
            BotCategory::SecurityTesting,
            "Failed for UA: {}",
            ua
        );
    }
}

#[test]
fn test_reference_crawlers_and_scrapers_classification() {
    let classifier = UserAgentClassifier::new();

    let ai_crawlers = ["duckassistbot", "agenttrustbot"];
    for ua in ai_crawlers {
        assert_eq!(
            classifier.classify(ua),
            BotCategory::AiCrawler,
            "Failed for AI UA: {}",
            ua
        );
    }

    let bad_scrapers = [
        "pandalytics",
        "recordedfuture",
        "techspybot",
        "superbot",
        "offline explorer",
    ];
    for ua in bad_scrapers {
        assert_eq!(
            classifier.classify(ua),
            BotCategory::BadScraper,
            "Failed for bad scraper UA: {}",
            ua
        );
    }
}

#[test]
fn test_reference_generic_tools_classification() {
    let classifier = UserAgentClassifier::new();

    let tools = [
        "okhttp/4.9.3",
        "fasthttp",
        "dart/2.19 (dart:io)",
        "alittle client",
        "quic-go-client",
        "libredtail",
    ];
    for ua in tools {
        assert_eq!(
            classifier.classify(ua),
            BotCategory::GenericTools,
            "Failed for tool UA: {}",
            ua
        );
    }
}

#[test]
fn test_system_and_mobile_services_classification() {
    let classifier = UserAgentClassifier::new();

    let services = [
        "AuthenticationServicesCore",
        "SamsungPass",
        "NetworkingExtension",
        "WordPress/6.4.3",
    ];
    for ua in services {
        assert_eq!(
            classifier.classify(ua),
            BotCategory::BrowserOrUnknown,
            "Failed for benign service UA: {}",
            ua
        );
    }
}
