from webtrust_auditor.website_scanner import (
    build_full_check_targets,
    is_full_check_exposure,
)


def get_target(path):
    return next(target for target in build_full_check_targets() if target["path"] == path)


def test_full_check_target_list_contains_many_paths():
    targets = build_full_check_targets()

    assert len(targets) >= 80


def test_full_check_target_list_contains_env_and_git_paths():
    paths = [target["path"] for target in build_full_check_targets()]

    assert "/.env" in paths
    assert "/.git/config" in paths
    assert "/phpinfo.php" in paths
    assert "/database.sql" in paths


def test_full_check_detects_env_file_exposure():
    target = get_target("/.env")

    response_info = {
        "status_code": 200,
        "content_type": "text/plain",
        "body_text": "APP_KEY=base64:test\nDB_PASSWORD=secret",
        "body_sample": b"APP_KEY=base64:test\nDB_PASSWORD=secret",
    }

    assert is_full_check_exposure(target, response_info, baseline_response=None) is True


def test_full_check_detects_git_config_exposure():
    target = get_target("/.git/config")

    response_info = {
        "status_code": 200,
        "content_type": "text/plain",
        "body_text": "[core]\nrepositoryformatversion = 0\nfilemode = true",
        "body_sample": b"[core]\nrepositoryformatversion = 0\nfilemode = true",
    }

    assert is_full_check_exposure(target, response_info, baseline_response=None) is True


def test_full_check_detects_phpinfo_exposure():
    target = get_target("/phpinfo.php")

    response_info = {
        "status_code": 200,
        "content_type": "text/html",
        "body_text": "<html><title>PHP Version 8.2</title>phpinfo()</html>",
        "body_sample": b"<html><title>PHP Version 8.2</title>phpinfo()</html>",
    }

    assert is_full_check_exposure(target, response_info, baseline_response=None) is True


def test_full_check_ignores_404_response():
    target = get_target("/.env")

    response_info = {
        "status_code": 404,
        "content_type": "text/html",
        "body_text": "Not Found",
        "body_sample": b"Not Found",
    }

    assert is_full_check_exposure(target, response_info, baseline_response=None) is False