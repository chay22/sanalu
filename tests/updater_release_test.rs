use sanalu::updater::{
    ReleaseAsset, ReleaseInfo, find_matching_asset, is_newer_version, parse_semver,
};

#[test]
fn test_parse_semver() {
    assert_eq!(parse_semver("0.1.0"), Some((0, 1, 0)));
    assert_eq!(parse_semver("v0.1.0"), Some((0, 1, 0)));
    assert_eq!(parse_semver("V1.2.3"), Some((1, 2, 3)));
    assert_eq!(parse_semver("  v2.10.5 \n"), Some((2, 10, 5)));
    assert_eq!(parse_semver("v1.2.3-beta"), Some((1, 2, 3)));
    assert_eq!(parse_semver("invalid"), None);
    assert_eq!(parse_semver("1.2"), None);
    assert_eq!(parse_semver(""), None);
}

#[test]
fn test_is_newer_version() {
    assert!(is_newer_version("0.1.0", "0.2.0"));
    assert!(is_newer_version("0.1.0", "v0.2.0"));
    assert!(is_newer_version("0.1.0", "1.0.0"));
    assert!(is_newer_version("0.1.9", "0.2.0"));
    assert!(is_newer_version("0.1.0", "0.1.1"));

    assert!(!is_newer_version("0.1.0", "0.1.0"));
    assert!(!is_newer_version("0.2.0", "0.1.9"));
    assert!(!is_newer_version("1.0.0", "0.9.9"));
    assert!(!is_newer_version("0.1.1", "0.1.0"));
    assert!(!is_newer_version("invalid", "0.2.0"));
    assert!(!is_newer_version("0.1.0", "invalid"));
}

#[test]
fn test_find_matching_asset_deb_and_tarball() {
    let assets = vec![
        ReleaseAsset {
            name: "sanalu_0.2.0_amd64.deb".into(),
            browser_download_url: "https://github.com/chay22/sanalu/releases/download/v0.2.0/sanalu_0.2.0_amd64.deb".into(),
            size: 4000000,
        },
        ReleaseAsset {
            name: "sanalu_0.2.0_arm64.deb".into(),
            browser_download_url: "https://github.com/chay22/sanalu/releases/download/v0.2.0/sanalu_0.2.0_arm64.deb".into(),
            size: 3800000,
        },
        ReleaseAsset {
            name: "sanalu-linux-x86_64.tar.gz".into(),
            browser_download_url: "https://github.com/chay22/sanalu/releases/download/v0.2.0/sanalu-linux-x86_64.tar.gz".into(),
            size: 3500000,
        },
        ReleaseAsset {
            name: "debian_packages.sha256".into(),
            browser_download_url: "https://github.com/chay22/sanalu/releases/download/v0.2.0/debian_packages.sha256".into(),
            size: 120,
        },
    ];

    let deb_x86 = find_matching_asset(&assets, "x86_64", true);
    assert!(deb_x86.is_some());
    assert_eq!(deb_x86.unwrap().name, "sanalu_0.2.0_amd64.deb");

    let deb_arm = find_matching_asset(&assets, "aarch64", true);
    assert!(deb_arm.is_some());
    assert_eq!(deb_arm.unwrap().name, "sanalu_0.2.0_arm64.deb");

    let tar_x86 = find_matching_asset(&assets, "x86_64", false);
    assert!(tar_x86.is_some());
    assert_eq!(tar_x86.unwrap().name, "sanalu-linux-x86_64.tar.gz");
}

#[test]
fn test_release_info_deserialization() {
    let json = r#"{
        "tag_name": "v0.2.0",
        "name": "Release v0.2.0",
        "body": "Bug fixes and improvements",
        "assets": [
            {
                "name": "sanalu_0.2.0_amd64.deb",
                "browser_download_url": "https://example.com/deb",
                "size": 12345
            }
        ]
    }"#;

    let info: ReleaseInfo = serde_json::from_str(json).unwrap();
    assert_eq!(info.tag_name, "v0.2.0");
    assert_eq!(info.assets.len(), 1);
    assert_eq!(info.assets[0].name, "sanalu_0.2.0_amd64.deb");
    assert_eq!(info.assets[0].size, 12345);
}
