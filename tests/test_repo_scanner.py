from webtrust_auditor.repo_scanner import scan_repository


def test_scan_repository_detects_github_token_pattern(tmp_path):
    token = "ghp_" + "a" * 36
    test_file = tmp_path / "demo.py"
    test_file.write_text(f'token = "{token}"', encoding="utf-8")

    result = scan_repository(str(tmp_path))

    titles = [finding["title"] for finding in result["findings"]]

    assert "Possible GitHub personal access token found" in titles


def test_scan_repository_detects_aws_key_pattern(tmp_path):
    aws_key = "AKIA" + "A" * 16
    test_file = tmp_path / "demo.py"
    test_file.write_text(f'aws_key = "{aws_key}"', encoding="utf-8")

    result = scan_repository(str(tmp_path))

    titles = [finding["title"] for finding in result["findings"]]

    assert "Possible AWS access key ID found" in titles


def test_scan_repository_detects_private_key_block(tmp_path):
    key_marker = "-----BEGIN " + "PRIVATE KEY-----"
    test_file = tmp_path / "demo.py"
    test_file.write_text(f'key_value = "{key_marker}"', encoding="utf-8")

    result = scan_repository(str(tmp_path))

    titles = [finding["title"] for finding in result["findings"]]

    assert "Possible Private key block found" in titles

def test_scan_repository_detects_jwt_like_token(tmp_path):
    jwt_header = "eyJ" + "a" * 20
    jwt_payload = "b" * 20
    jwt_signature = "c" * 20
    jwt_token = f"{jwt_header}.{jwt_payload}.{jwt_signature}"

    test_file = tmp_path / "demo.py"
    test_file.write_text(f'jwt_token = "{jwt_token}"', encoding="utf-8")

    result = scan_repository(str(tmp_path))

    titles = [finding["title"] for finding in result["findings"]]

    assert "Possible JWT-like token found" in titles