INSERT INTO rule_allow_list (description, regexes, paths, commits, stop_words) VALUES
    ('global allow lists', NULL, 'gitleaks.toml', NULL, 'getenv,env_'); -- 1

INSERT INTO rule_pack (version, global_allow_list, active, created) VALUES
    ('0.0.0', 1, 0, '2023-07-12 00:00:00.000'), -- 1
    ('1.0.0', 1, 1, '2023-07-14 00:00:00.000'); -- 2

INSERT INTO rules (rule_pack, allow_list, rule_name, description, entropy, secret_group, regex, [path], keywords) VALUES
    ('0.0.0', NULL, 'github-oauth', 'GitHub OAuth Access Token', NULL, NULL, 'ya29\\.[0-9A-Za-z\\-_]++', NULL, NULL), -- 1
    ('1.0.0', NULL, 'github-oauth', 'GitHub OAuth Access Token', NULL, NULL, 'ya29\\.[0-9A-Za-z\\-_]++', NULL, NULL), -- 2
    ('1.0.0', NULL, 'github-pat', 'GitHub Personal Access Token', NULL, NULL, '(ghu|ghs|gho|ghp|ghr)_[0-9a-zA-Z]{36}', NULL, 'ghu_,ghs_,gho_,ghp_,ghr_'), -- 3
    ('1.0.0', NULL, 'private-key', 'Secret Key', NULL, NULL, 'regex-secret-key', NULL, NULL); -- 4

INSERT INTO tag (name) VALUES
    ('Cli'), -- 1
    ('Warn'); -- 2

INSERT INTO rule_tag (rule_id, tag_id) VALUES
    (1, 2), -- 1
    (2, 2), -- 2
    (3, 1), -- 3
    (2, 1); -- 4

INSERT INTO vcs_instance (name, provider_type, scheme, hostname, port, organization, vcs_scope, exceptions) VALUES
    ('AZURE_DEVOPS_ACCEPTANCE', 'AZURE_DEVOPS', 'https', 'fake-dev.azure.com', 443, 'ado-org', 'ado-project1,ado-project2', NULL), -- 1
    ('BITBUCKET_DEV', 'BITBUCKET', 'https', 'fake-bitbucket.com', 443, NULL, NULL, NULL); -- 2

INSERT INTO repository (vcs_instance, project_key, repository_id, repository_name, repository_url) VALUES
   (1, 'ado-project1', 'r1', 'resc-dummy1', 'https://fake-dev.azure.com/ado-org/ado-project1/_git/resc-dummy1'), -- 1
   (1, 'ado-project2', 'r2', 'resc-dummy2', 'https://fake-dev.azure.com/ado-org/ado-project2/_git/resc-dummy2'), -- 2
   (2, 'btbk-project1', 'r3', 'resc-dummy3', 'https://fake-bitbucket.com/scm/r3/resc-dummy3.git'); -- 3

INSERT INTO scan (rule_pack, scan_type, last_scanned_commit, [timestamp], increment_number, repository_id, is_latest) VALUES
   ('0.0.0', 'BASE', 'qwerty1', '2023-07-12 00:00:00.000', 0, 1, 1), -- 1
   ('0.0.0', 'INCREMENTAL', 'qwerty2', '2023-07-13 00:00:00.000', 1, 1, 1), -- 2
   ('1.0.0', 'BASE', 'qwerty1', '2023-07-14 00:00:00.000', 0, 1, 1), -- 3
   ('1.0.0', 'INCREMENTAL', 'qwerty2', '2023-07-15 00:00:00.000', 1, 1, 1), -- 4
   ('1.0.0', 'BASE', 'qwerty3', '2023-07-14 00:00:00.000', 0, 2, 1), -- 5
   ('1.0.0', 'INCREMENTAL', 'qwerty4', '2023-07-15 00:00:00.000', 1, 2, 1); -- 6

INSERT INTO finding (repository_id, rule_name, file_path, line_number, commit_id, commit_message, commit_timestamp, author, email, event_sent_on, column_start, column_end, is_dir_scan) VALUES
   (1, 'github-oauth', 'application.txt', 1, 'qwerty1', 'this is commit 1', '2023-01-01 00:00:00.000', 'developer', 'developer@abc.com', NULL, 1, 100, 0), -- 1
   (1, 'github-pat', 'application.txt', 2, 'qwerty2', 'this is commit 2', '2023-01-02 00:00:00.000', 'developer', 'developer@abc.com', NULL, 1, 80, 0), -- 2
   (2, 'github-oauth', 'application.txt', 1, 'qwerty3', 'this is commit 1', '2023-01-01 00:00:00.000', 'developer', 'developer@abc.com', NULL, 1, 100, 0), -- 3
   (2, 'github-oauth', 'application.txt', 1, 'qwerty4', 'this is commit 2', '2023-01-02 00:00:00.000', 'developer', 'developer@abc.com', NULL, 1, 100, 0), -- 4
   (2, 'github-pat', 'application.txt', 2, 'qwerty3', 'this is commit 1', '2023-01-01 00:00:00.000', 'developer', 'developer@abc.com', NULL, 1, 80, 0), -- 5
   (2, 'github-pat', 'application.txt', 2, 'qwerty4', 'this is commit 2', '2023-01-02 00:00:00.000', 'developer', 'developer@abc.com', NULL, 1, 80, 0); -- 6

INSERT INTO scan_finding(scan_id, finding_id) VALUES
   (1, 1),
   (3, 1),
   (3, 2),
   (5, 3),
   (6, 4),
   (5, 5),
   (6, 6);

INSERT INTO audit(finding_id, [status], auditor, comment, [timestamp], is_latest) VALUES
   (1, 'NOT_ANALYZED', 'Anonymous', NULL, '2023-07-20 00:00:00.000', 0), -- 1
   (1, 'TRUE_POSITIVE', 'Anonymous', 'It is a true positive issue', '2023-07-21 00:00:00.000', 1); -- 2