import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).parent
TEXT_SUFFIXES = {".html", ".json", ".md", ".py", ".sh", ".yaml", ".yml"}
ADMIN = "adm" + "in"
ADMIN_123 = ADMIN + "123"
VULHUB = "vul" + "hub"
FLARUM = "fla" + "rum"
DEMO_TOKEN = "test-api-" + "token-12345"
FIXED_SESSION_KEY = "01234567" + "89ABCDEF"
FORBIDDEN_LITERALS = (
    f'ADMIN_PASSWORD = "{ADMIN_123}"',
    f'PASSWORD = "{ADMIN}"',
    f'PASSWORD = "{VULHUB}"',
    f'"password": "{ADMIN_123}"',
    f'"password": "{FLARUM}"',
    f'MYSQL_ROOT_PASSWORD={FLARUM}',
    f'MYSQL_PASSWORD={FLARUM}',
    f'LABEL_STUDIO_PASSWORD={ADMIN_123}',
    f'LABEL_STUDIO_USER_TOKEN={DEMO_TOKEN}',
    f'app.secret_key = "{FIXED_SESSION_KEY}"',
    'MYSQL_ROOT_PASSWORD=vu' + 'find',
    'MYSQL_PASSWORD=vu' + 'find',
    'MYSQL_ROOT_PASSWORD=ro' + 'ot',
    'POSTGRES_PASSWORD: ' + VULHUB,
    'JOOMLA_DB_PASSWORD=' + VULHUB,
    'MYSQL_ROOT_PASSWORD=' + VULHUB,
    '-p' + 'root',
)


class PublicSecretHygieneTest(unittest.TestCase):
    def test_public_snapshot_has_no_known_demo_credentials_in_secret_formats(self):
        findings: list[str] = []
        for path in REPO_ROOT.rglob("*"):
            if path == Path(__file__) or not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for literal in FORBIDDEN_LITERALS:
                if literal in text:
                    findings.append(f"{path.relative_to(REPO_ROOT)}: {literal}")
        self.assertEqual([], findings, "\n".join(findings))


if __name__ == "__main__":
    unittest.main()
