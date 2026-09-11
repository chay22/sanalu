use sanalu::discovery::nginx::{find_active_nginx_conf, find_active_nginx_conf_with_paths};
use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_find_conf_from_proc_cmdline() {
    let dir = tempdir().unwrap();
    let proc_dir = dir.path().join("proc");
    let pid_dir = proc_dir.join("1234");
    fs::create_dir_all(&pid_dir).unwrap();
    let mut cmdline = File::create(pid_dir.join("cmdline")).unwrap();
    cmdline
        .write_all(b"nginx: master process\0-c\0/etc/nginx/custom.conf\0")
        .unwrap();

    let found = find_active_nginx_conf_with_paths(&proc_dir, &[], &[]);
    assert_eq!(found.to_str().unwrap(), "/etc/nginx/custom.conf");
}

#[test]
fn test_find_conf_from_systemd_unit() {
    let dir = tempdir().unwrap();
    let proc_dir = dir.path().join("proc");
    let systemd_dir = dir.path().join("systemd");
    fs::create_dir_all(&systemd_dir).unwrap();
    let mut unit = File::create(systemd_dir.join("nginx.service")).unwrap();
    unit.write_all(b"[Service]\nExecStart=/usr/sbin/nginx -c /opt/nginx/service.conf\n")
        .unwrap();

    let found = find_active_nginx_conf_with_paths(&proc_dir, &[systemd_dir.as_path()], &[]);
    assert_eq!(found.to_str().unwrap(), "/opt/nginx/service.conf");
}

#[test]
fn test_find_conf_fallback() {
    let dir = tempdir().unwrap();
    let proc_dir = dir.path().join("proc");
    let fallback = dir.path().join("nginx.conf");
    File::create(&fallback).unwrap();

    let found = find_active_nginx_conf_with_paths(&proc_dir, &[], &[fallback.as_path()]);
    assert_eq!(found, fallback);
}

#[test]
fn test_find_conf_default_empty_fallback() {
    let dir = tempdir().unwrap();
    let proc_dir = dir.path().join("proc");
    let found = find_active_nginx_conf_with_paths(&proc_dir, &[], &[]);
    assert_eq!(found.to_str().unwrap(), "/etc/nginx/nginx.conf");
}

#[test]
fn test_find_active_nginx_conf_smoke() {
    let conf = find_active_nginx_conf();
    assert!(!conf.as_os_str().is_empty());
}
