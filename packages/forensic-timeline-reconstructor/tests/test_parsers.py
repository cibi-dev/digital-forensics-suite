"""Tests for forensic log parsers: Syslog, Auth.log, Nginx, JSON-Lines."""

import os
import tempfile
import pytest

from timeline.parsers.syslog import SyslogParser, parse_pri, parse_structured_data
from timeline.parsers.auth import AuthLogParser
from timeline.parsers.nginx import NginxParser
from timeline.parsers.json_lines import JsonLinesParser


# --- Syslog Tests ---

def test_parse_pri() -> None:
    fac, sev = parse_pri(165)
    assert fac == "local4"
    assert sev == "NOTICE"

    fac_auth, sev_auth = parse_pri(34)
    assert fac_auth == "auth"
    assert sev_auth == "CRITICAL"


def test_parse_structured_data() -> None:
    sd_raw = '[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][secondID param="val"]'
    sd = parse_structured_data(sd_raw)
    assert "exampleSDID@32473" in sd
    assert sd["exampleSDID@32473"]["iut"] == "3"
    assert sd["exampleSDID@32473"]["eventSource"] == "Application"
    assert sd["secondID"]["param"] == "val"

    assert parse_structured_data("-") == {}
    assert parse_structured_data(None) == {}


def test_syslog_rfc5424_parser() -> None:
    parser = SyslogParser()
    line = '<165>1 2023-10-11T22:14:15.003Z myhost.net app 1234 ID47 [test@123 key="val"] User login succeeded'
    evt = parser.parse_line(line, line_number=1, source_file="syslog.log")

    assert evt is not None
    assert evt.source_type == "syslog"
    assert evt.facility == "local4"
    assert evt.severity == "NOTICE"
    assert evt.host == "myhost.net"
    assert evt.process == "app"
    assert evt.pid == 1234
    assert evt.message == "User login succeeded"
    assert evt.metadata["msg_id"] == "ID47"
    assert evt.metadata["test@123"]["key"] == "val"


def test_syslog_rfc3164_parser() -> None:
    parser = SyslogParser(default_year=2023)
    line = "Oct 11 22:14:15 server01 su[9876]: 'su root' failed for cibi on /dev/pts/1"
    evt = parser.parse_line(line, line_number=5, source_file="syslog.log")

    assert evt is not None
    assert evt.host == "server01"
    assert evt.process == "su"
    assert evt.pid == 9876
    assert evt.message == "'su root' failed for cibi on /dev/pts/1"

    # RFC 3164 without tag
    line_notag = "Oct 11 22:14:16 server01 Kernel memory initialized"
    evt_notag = parser.parse_line(line_notag, line_number=6)
    assert evt_notag is not None
    assert evt_notag.message == "Kernel memory initialized"
    assert evt_notag.process is None


def test_syslog_file_streaming() -> None:
    parser = SyslogParser(default_year=2023)
    content = (
        "<34>Oct 11 22:14:15 web01 sshd[100]: session started\n"
        "Oct 11 22:14:16 web01 sshd[100]: session closed\n"
        "corrupt line that should not crash the parser\n"
    )
    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write(content)
        tf_path = tf.name

    try:
        events = list(parser.parse_file(tf_path))
        assert len(events) == 2
        assert events[0].line_number == 1
        assert events[1].line_number == 2
    finally:
        os.unlink(tf_path)


# --- Auth Log Tests ---

def test_auth_parser_ssh_events() -> None:
    parser = AuthLogParser(default_year=2023)

    # Accepted publickey
    l_acc = "Oct 11 22:14:15 authsrv sshd[2400]: Accepted publickey for ubuntu from 192.168.1.50 port 54321 ssh2: RSA SHA256:abc"
    e_acc = parser.parse_line(l_acc)
    assert e_acc is not None
    assert e_acc.action == "SSH_LOGIN_SUCCESS"
    assert e_acc.user == "ubuntu"
    assert e_acc.client_ip == "192.168.1.50"
    assert e_acc.metadata["port"] == 54321
    assert e_acc.metadata["auth_method"] == "publickey"

    # Failed password for invalid user
    l_fail_inv = "Oct 11 22:14:16 authsrv sshd[2401]: Failed password for invalid user admin from 10.0.0.99 port 44332 ssh2"
    e_fail_inv = parser.parse_line(l_fail_inv)
    assert e_fail_inv is not None
    assert e_fail_inv.action == "SSH_LOGIN_FAILED_INVALID_USER"
    assert e_fail_inv.user == "admin"
    assert e_fail_inv.client_ip == "10.0.0.99"
    assert e_fail_inv.severity == "WARNING"

    # Failed password standard
    l_fail = "Oct 11 22:14:17 authsrv sshd[2402]: Failed password for root from 10.0.0.99 port 44333 ssh2"
    e_fail = parser.parse_line(l_fail)
    assert e_fail is not None
    assert e_fail.action == "SSH_LOGIN_FAILED"
    assert e_fail.user == "root"

    # SSH disconnect
    l_disc = "Oct 11 22:14:18 authsrv sshd[2403]: Disconnected from authenticating user root 10.0.0.99 port 44333 [preauth]"
    e_disc = parser.parse_line(l_disc)
    assert e_disc is not None
    assert e_disc.action == "SSH_DISCONNECT"
    assert e_disc.client_ip == "10.0.0.99"


def test_auth_parser_sudo_and_pam() -> None:
    parser = AuthLogParser(default_year=2023)

    # Sudo command
    l_sudo = "Oct 11 22:15:00 authsrv sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    e_sudo = parser.parse_line(l_sudo)
    assert e_sudo is not None
    assert e_sudo.action == "SUDO_COMMAND"
    assert e_sudo.user == "ubuntu"
    assert e_sudo.metadata["target_user"] == "root"
    assert e_sudo.metadata["command"] == "/bin/cat /etc/shadow"
    assert e_sudo.metadata["pwd"] == "/home/ubuntu"

    # Sudo PAM open / close
    l_open = "Oct 11 22:15:01 authsrv sudo: pam_unix(sudo:session): session opened for user root(uid=0) by ubuntu(uid=1000)"
    e_open = parser.parse_line(l_open)
    assert e_open is not None
    assert e_open.action == "PAM_SESSION_OPEN"
    assert e_open.user == "ubuntu"

    l_close = "Oct 11 22:15:05 authsrv sudo: pam_unix(sudo:session): session closed for user root"
    e_close = parser.parse_line(l_close)
    assert e_close is not None
    assert e_close.action == "PAM_SESSION_CLOSE"

    # Sudo failed
    l_sfail = "Oct 11 22:15:10 authsrv sudo:   cibi : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/cibi ; USER=root ; COMMAND=/bin/su"
    e_sfail = parser.parse_line(l_sfail)
    assert e_sfail is not None
    assert e_sfail.action == "SUDO_FAILED_AUTH"
    assert e_sfail.severity == "ALERT"

    # Useradd & Passwd
    l_uadd = "Oct 11 22:16:00 authsrv useradd[3000]: new user: name=backdoor, UID=1001, GID=1001"
    e_uadd = parser.parse_line(l_uadd)
    assert e_uadd is not None
    assert e_uadd.action == "USER_CREATED"
    assert e_uadd.user == "backdoor"
    assert e_uadd.severity == "CRITICAL"

    l_pw = "Oct 11 22:16:05 authsrv passwd[3001]: password changed for backdoor"
    e_pw = parser.parse_line(l_pw)
    assert e_pw is not None
    assert e_pw.action == "PASSWORD_CHANGED"
    assert e_pw.user == "backdoor"


# --- Nginx Parser Tests ---

def test_nginx_access_log_parser() -> None:
    parser = NginxParser()
    line_200 = '192.168.1.100 - frank [10/Oct/2023:13:55:36 +0000] "GET /api/v1/data HTTP/1.1" 200 1024 "https://ref.com" "Mozilla/5.0"'
    evt_200 = parser.parse_line(line_200)
    assert evt_200 is not None
    assert evt_200.source_type == "nginx_access"
    assert evt_200.client_ip == "192.168.1.100"
    assert evt_200.user == "frank"
    assert evt_200.severity == "INFO"
    assert evt_200.metadata["method"] == "GET"
    assert evt_200.metadata["url"] == "/api/v1/data"
    assert evt_200.metadata["status_code"] == 200
    assert evt_200.metadata["bytes_sent"] == 1024
    assert evt_200.metadata["user_agent"] == "Mozilla/5.0"

    # 404 warning
    line_404 = '10.0.0.5 - - [10/Oct/2023:13:55:37 +0000] "GET /admin.php HTTP/1.1" 404 150 "-" "-"'
    evt_404 = parser.parse_line(line_404)
    assert evt_404 is not None
    assert evt_404.severity == "WARNING"
    assert evt_404.user is None

    # 500 error
    line_500 = '10.0.0.5 - - [10/Oct/2023:13:55:38 +0000] "POST /api/crash HTTP/1.1" 500 50 "-" "-"'
    evt_500 = parser.parse_line(line_500)
    assert evt_500 is not None
    assert evt_500.severity == "ERROR"


def test_nginx_error_log_parser() -> None:
    parser = NginxParser()
    line_err = '2023/10/11 12:34:56 [error] 1234#0: *10 open() "/var/www/missing" failed (2: No such file), client: 192.168.1.50, server: example.com, request: "GET /missing HTTP/1.1", host: "example.com"'
    evt = parser.parse_line(line_err)
    assert evt is not None
    assert evt.source_type == "nginx_error"
    assert evt.severity == "ERROR"
    assert evt.pid == 1234
    assert evt.client_ip == "192.168.1.50"
    assert evt.host == "example.com"
    assert evt.metadata["cid"] == 10
    assert evt.metadata["request"] == "GET /missing HTTP/1.1"


# --- JSON-Lines Tests ---

def test_json_lines_parser() -> None:
    parser = JsonLinesParser()
    line_json = (
        '{"timestamp": "2023-10-11T20:00:00.123456Z", "level": "error", "host": "prod-node-1", '
        '"process": "auth-service", "pid": 456, "user": "admin", "client_ip": "1.2.3.4", '
        '"action": "TOKEN_REVOKED", "message": "Admin token revoked", "custom_key": "custom_val"}'
    )
    evt = parser.parse_line(line_json)
    assert evt is not None
    assert evt.source_type == "json_lines"
    assert evt.severity == "ERROR"
    assert evt.host == "prod-node-1"
    assert evt.process == "auth-service"
    assert evt.pid == 456
    assert evt.user == "admin"
    assert evt.client_ip == "1.2.3.4"
    assert evt.action == "TOKEN_REVOKED"
    assert evt.message == "Admin token revoked"
    assert evt.metadata["custom_key"] == "custom_val"

    # Epoch timestamp JSON-line
    line_epoch = '{"ts": 1697062455, "msg": "Epoch event", "level": "warn"}'
    evt_epoch = parser.parse_line(line_epoch)
    assert evt_epoch is not None
    assert evt_epoch.message == "Epoch event"
    assert evt_epoch.severity == "WARNING"

    # Comments and empty lines
    assert parser.parse_line("# Comment") is None
    assert parser.parse_line("") is None
    assert parser.parse_line("{invalid-json") is None
    assert parser.parse_line('{"no_timestamp": true}') is None


def test_convenience_file_parsers(tmp_path) -> None:
    from timeline.parsers.auth import parse_auth_file
    from timeline.parsers.nginx import parse_nginx_file
    from timeline.parsers.json_lines import parse_jsonl_file
    from timeline.parsers.syslog import parse_syslog_file

    auth_f = tmp_path / "c_auth.log"
    auth_f.write_text("Oct 11 10:00:00 srv sshd[10]: Accepted password for root from 1.2.3.4 port 22 ssh2\n")
    assert len(list(parse_auth_file(str(auth_f), default_year=2023))) == 1

    nginx_f = tmp_path / "c_nginx.log"
    nginx_f.write_text('1.2.3.4 - - [10/Oct/2023:10:00:00 +0000] "GET /test HTTP/1.1" 200 50 "-" "-"\n')
    assert len(list(parse_nginx_file(str(nginx_f)))) == 1

    jsonl_f = tmp_path / "c_json.jsonl"
    jsonl_f.write_text('{"timestamp": "2023-10-11T10:00:00Z", "message": "msg"}\n')
    assert len(list(parse_jsonl_file(str(jsonl_f)))) == 1

    syslog_f = tmp_path / "c_syslog.log"
    syslog_f.write_text("<165>1 2023-10-11T10:00:00Z host app 10 ID1 - msg\n")
    assert len(list(parse_syslog_file(str(syslog_f)))) == 1

