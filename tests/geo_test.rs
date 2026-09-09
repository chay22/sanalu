use sanalu::geo::IpLookupDb;

#[test]
fn test_parse_tsv_and_lookup() {
    let tsv_data = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
                    8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n\
                    103.10.10.0\t103.10.10.255\t23700\tID\tINDOSAT\n";
    let db = IpLookupDb::from_tsv_reader(tsv_data.as_bytes()).unwrap();

    let meta = db
        .lookup("8.8.8.8".parse().unwrap())
        .expect("lookup google ip");
    assert_eq!(meta.asn, 15169);
    assert_eq!(&meta.country, b"US");

    let id_meta = db
        .lookup("103.10.10.5".parse().unwrap())
        .expect("lookup id ip");
    assert_eq!(id_meta.asn, 23700);
    assert_eq!(&id_meta.country, b"ID");

    assert!(db.lookup("192.168.1.1".parse().unwrap()).is_none());
}
