use sanalu::daemon::replay_log_file;
use std::path::Path;

#[test]
fn test_replay_reference_nginx_access_log() {
    let access_log = Path::new("references/ubuntu22/nginx/access.log");
    if access_log.exists() {
        let threats = replay_log_file(access_log, &[]).expect("replay access log");
        assert!(threats > 0);
    }
}

#[test]
fn test_replay_reference_auth_log() {
    let auth_log = Path::new("references/ubuntu22/auth/auth.log");
    if auth_log.exists() {
        let threats = replay_log_file(auth_log, &[]).expect("replay auth log");
        assert!(threats > 0);
    }
}
