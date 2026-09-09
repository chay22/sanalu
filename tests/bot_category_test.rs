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

    assert!(BotCategory::SecurityTesting.is_blocked_by_default());
    assert!(BotCategory::AiCrawler.is_blocked_by_default());
    assert!(BotCategory::BadScraper.is_blocked_by_default());
    assert!(BotCategory::GenericTools.is_blocked_by_default());
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
    assert_eq!(classifier.classify("-"), BotCategory::GenericTools);
    assert_eq!(classifier.classify(""), BotCategory::GenericTools);

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
