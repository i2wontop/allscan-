"""Offline unit tests for allscan.

These tests never touch the network: the engine tests patch the module
registry with in-memory stubs, and everything else exercises pure data/logic
(models, reporting, diffing, config, validation, secret scanning).

Run with:  pytest -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import allscan.engine as engine_mod
from allscan.base import Module
from allscan.config import Config, DEFAULTS
from allscan.engine import Engine
from allscan.models import Category, Finding, ScanResult, Severity
from allscan.utils import (
    RateLimiter,
    ScanCancelled,
    normalize_target,
    scan_for_secrets,
    validate_target,
)
from allscan import report


# --------------------------------------------------------------------------- #
# stub modules (no network)
# --------------------------------------------------------------------------- #


class StubRecon(Module):
    name = "recon"
    label = "recon"

    def run(self, ctx):
        ctx.log("discovering")
        ctx.state["hosts"] = {"a.example.test": ["203.0.113.1"]}
        return [
            ctx.emit(
                Finding(
                    category=Category.SUBDOMAIN,
                    title="a.example.test",
                    target="example.test",
                )
            )
        ]


class StubScan(Module):
    name = "scan"
    label = "scan"

    def run(self, ctx):
        ctx.cancel.raise_if_cancelled()
        return [
            ctx.emit(
                Finding(
                    category=Category.PORT,
                    title="203.0.113.1:80 open",
                    severity=Severity.INFO,
                )
            )
        ]


class BoomModule(Module):
    name = "web"
    label = "web"

    def run(self, ctx):
        raise RuntimeError("kaboom")


@pytest.fixture
def stub_registry(monkeypatch):
    reg = {"recon": StubRecon(), "scan": StubScan(), "web": BoomModule()}
    monkeypatch.setattr(engine_mod, "get_registry", lambda: reg)
    return reg


# --------------------------------------------------------------------------- #
# validation / utils
# --------------------------------------------------------------------------- #


def test_normalize_target_strips_scheme_port_path():
    assert normalize_target("https://Example.COM:8443/a/b?x=1") == "example.com"
    assert normalize_target("http://10.0.0.1/") == "10.0.0.1"


@pytest.mark.parametrize(
    "value,ok",
    [
        ("example.com", True),
        ("sub.example.co.uk", True),
        ("8.8.8.8", True),
        ("::1", True),
        ("not a host", False),
        ("", False),
    ],
)
def test_validate_target(value, ok):
    assert validate_target(value)[0] is ok


def test_rate_limiter_zero_is_noop():
    rl = RateLimiter(0)
    rl.acquire()  # must not block or raise


def test_scan_for_secrets_finds_and_truncates():
    text = 'aws="AKIAIOSFODNN7EXAMPLE" token: "ghp_' + "a" * 40 + '"'
    hits = {label for label, _ in scan_for_secrets(text)}
    assert "AWS Access Key ID" in hits
    assert any("GitHub" in h for h in hits)


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #


def test_finding_dedupe_keeps_highest_severity():
    r = ScanResult(target="example.test")
    r.add(Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.LOW))
    r.add(Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.MEDIUM))
    assert len(r.findings) == 1
    assert r.findings[0].severity is Severity.MEDIUM


def test_scanresult_roundtrip():
    r = ScanResult(target="example.test")
    r.add(Finding(category=Category.CVE, title="CVE-1", severity=Severity.HIGH, evidence={"x": 1}))
    data = r.to_dict()
    r2 = ScanResult.from_dict(data)
    assert r2.target == "example.test"
    assert r2.findings[0].severity is Severity.HIGH
    assert r2.findings[0].evidence == {"x": 1}


def test_severity_ordering():
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH


# --------------------------------------------------------------------------- #
# engine
# --------------------------------------------------------------------------- #


def test_engine_runs_in_order_and_collects(stub_registry):
    cfg = Config(modules=["scan", "recon"], rate_limit=0)
    statuses = []
    eng = Engine("example.test", cfg, on_status=lambda m, s: statuses.append((m, s)))
    result = eng.run()
    # canonical order forces recon before scan despite config order
    assert result.modules_run == ["recon", "scan"]
    titles = {f.title for f in result.findings}
    assert "a.example.test" in titles
    assert any(m == "recon" and s == "done" for m, s in statuses)


def test_engine_module_error_is_isolated(stub_registry):
    cfg = Config(modules=["recon", "web", "scan"], rate_limit=0)
    errors = []
    eng = Engine(
        "example.test",
        cfg,
        on_status=lambda m, s: errors.append((m, s)) if s == "error" else None,
    )
    result = eng.run()
    # web blew up but recon+scan still ran and were recorded
    assert "recon" in result.modules_run and "scan" in result.modules_run
    assert "web" not in result.modules_run
    assert ("web", "error") in errors


def test_engine_cancel_yields_partial(stub_registry):
    cfg = Config(modules=["recon", "scan"], rate_limit=0)
    eng = Engine("example.test", cfg)
    eng.request_cancel()
    result = eng.run()
    assert result.partial is True


# --------------------------------------------------------------------------- #
# reporting + diff
# --------------------------------------------------------------------------- #


def _sample(target="example.test", extra=None):
    r = ScanResult(target=target)
    r.add(Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.MEDIUM))
    if extra:
        r.add(extra)
    r.finished_at = r.started_at + 1
    return r


def test_save_and_list_runs(tmp_path: Path):
    r = _sample()
    jp = report.save_json(r, tmp_path)
    report.save_markdown(r, tmp_path)
    report.save_html(r, tmp_path)
    assert jp.exists()
    runs = report.list_runs(tmp_path)
    assert len(runs) == 1
    assert runs[0].target == "example.test"


def test_reports_written_as_utf8_with_unicode_glyphs(tmp_path: Path):
    # Reports contain non-ASCII glyphs (arrows, box-drawing). On Windows the
    # default text encoding is cp1252, which can't encode e.g. U+2193 and
    # would raise UnicodeEncodeError on save. Writers must force UTF-8.
    r = ScanResult(target="example.test")
    r.add(Finding(category=Category.HEADER,
                  title="Trend ↓ → ✔ █",
                  severity=Severity.HIGH,
                  description="arrows ↓↑→ box ─│"))
    r.finished_at = r.started_at + 1
    jp = report.save_json(r, tmp_path)
    mp = report.save_markdown(r, tmp_path)
    hp = report.save_html(r, tmp_path)
    # Round-trips only succeed if bytes were written and read back as UTF-8.
    assert "↓" in mp.read_text(encoding="utf-8")
    assert "↓" in hp.read_text(encoding="utf-8")
    assert report.load_json(jp).target == "example.test"


def test_markdown_and_html_contain_findings():
    r = _sample()
    md = report.to_markdown(r)
    html = report.to_html(r)
    assert "Missing CSP" in md and "Missing CSP" in html
    assert "example.test" in html


def test_diff_added_removed():
    old = _sample()
    new = _sample(
        extra=Finding(category=Category.TLS, title="Weak TLS", severity=Severity.HIGH)
    )
    # remove the CSP finding from new to make it "resolved"
    new.findings = [f for f in new.findings if f.title != "Missing CSP"]
    d = report.diff_runs(old, new)
    assert any(f.title == "Weak TLS" for f in d.added)
    assert any(f.title == "Missing CSP" for f in d.removed)


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #


def test_config_coerces_bad_numeric_yaml(tmp_path):
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text('threads: "abc"\nrate_limit: "fast"\ntimeout: xyz\n')
    cfg = Config.load(str(cfg_file))
    assert cfg.threads == DEFAULTS["threads"]
    assert cfg.rate_limit == DEFAULTS["rate_limit"]
    assert cfg.timeout == DEFAULTS["timeout"]


def test_config_malformed_yaml_raises_valueerror(tmp_path):
    cfg_file = tmp_path / "bad.yaml"
    cfg_file.write_text("threads: [unclosed\n: : :\n")
    import pytest as _pytest
    with _pytest.raises(ValueError):
        Config.load(str(cfg_file))


def test_run_cli_swallows_unexpected_and_ctrl_c(monkeypatch):
    import allscan.main as main_mod

    monkeypatch.setattr(main_mod, "main", lambda argv=None: (_ for _ in ()).throw(RuntimeError("boom")))
    assert main_mod.run_cli([]) == 1  # no traceback escapes

    monkeypatch.setattr(main_mod, "main", lambda argv=None: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert main_mod.run_cli([]) == 130


def test_cmd_diff_missing_file_returns_2():
    from allscan.main import main
    assert main(["diff", "/no/such1.json", "/no/such2.json"]) == 2


def test_output_path_falls_back_when_unwritable(tmp_path):
    # configured dir is impossible (a path *under a regular file*) -> must not
    # raise; it falls back to a writable location and remembers it.
    f = tmp_path / "afile"
    f.write_text("x")
    cfg = Config(output_dir=str(f / "cannot" / "here"))
    out = cfg.output_path()
    assert out.is_dir()
    assert cfg.output_dir == str(out)  # remembered for later saves
    # a normal writable dir is used as-is
    cfg2 = Config(output_dir=str(tmp_path / "ok"))
    assert cfg2.output_path() == (tmp_path / "ok")


def test_config_overrides_skip_none():
    cfg = Config()
    out = cfg.apply_overrides(threads=None, rate_limit=99.0)
    assert out.threads == cfg.threads  # None left untouched
    assert out.rate_limit == 99.0


# --------------------------------------------------------------------------- #
# Allscan "run everything" entry point
# --------------------------------------------------------------------------- #


def test_cli_all_flag_forces_full_chain():
    from allscan.engine import MODULE_ORDER
    from allscan.main import build_parser, config_from_args

    # --all overrides a narrower --modules
    args = build_parser().parse_args(["example.test", "--all", "--modules", "web"])
    assert args.run_all is True
    assert config_from_args(args).modules == list(MODULE_ORDER)


# --------------------------------------------------------------------------- #
# expanded modules: offline logic tests
# --------------------------------------------------------------------------- #


def _make_ctx(target="example.test", state=None):
    """Build an offline ModuleContext (no network, no-op callbacks)."""
    from allscan.base import ModuleContext
    from allscan.utils import AuditLog, CancelToken, RateLimiter

    return ModuleContext(
        target=target,
        config=Config(rate_limit=0),
        rate=RateLimiter(0),
        audit=AuditLog(None),
        cancel=CancelToken(),
        state=state if state is not None else {},
        _log=lambda m, msg: None,
        _on_finding=lambda f: None,
        _module_name="test",
    )


def test_registry_order_labels_consistent():
    from allscan.base import get_registry
    from allscan.config import MODULE_LABELS
    from allscan.engine import MODULE_ORDER

    reg = set(get_registry())
    assert reg == set(MODULE_ORDER) == set(MODULE_LABELS)
    # compliance must run last so it can roll up everything
    assert MODULE_ORDER[-1] == "compliance"


def test_compliance_evaluate_flags_issues():
    from allscan.compliance import evaluate, summarize

    findings = [
        Finding(category=Category.HEADER, title="Missing content-security-policy header"),
        Finding(category=Category.TLS, title="Deprecated protocol accepted: TLSv1.0 on x",
                severity=Severity.MEDIUM),
        Finding(category=Category.EMAIL, title="Missing SPF record", severity=Severity.MEDIUM),
        Finding(category=Category.CLOUD, title="AWS S3 bucket publicly listable: http://x",
                severity=Severity.HIGH),
    ]
    rows = evaluate(findings)
    by_id = {r["id"]: r for r in rows}
    assert by_id["hdr_content-security-policy"]["status"] == "fail"
    assert by_id["tls_protocols"]["status"] == "fail"
    assert by_id["email_spf"]["status"] == "fail"
    assert by_id["exp_bucket"]["status"] == "fail"
    # a check with no corresponding finding passes
    assert by_id["dns_axfr"]["status"] == "pass"
    counts = summarize(rows)
    assert counts["fail"] >= 4


def test_compliance_module_reads_prior_findings():
    from allscan.compliance import ComplianceModule

    result = ScanResult(target="example.test")
    result.add(Finding(category=Category.EMAIL, title="Missing DMARC record",
                       severity=Severity.MEDIUM))
    ctx = _make_ctx(state={"_result": result})
    out = ComplianceModule().run(ctx)
    # summary finding + at least the DMARC fail line
    assert any(f.category == Category.COMPLIANCE and "checklist" in f.title.lower()
               for f in out)
    assert ctx.state.get("compliance")  # stashed for the report
    assert any(r["id"] == "email_dmarc" and r["status"] == "fail"
               for r in ctx.state["compliance"])


def test_cloud_extract_buckets():
    from allscan.cloud import CloudModule

    corpus = (
        "see https://my-bucket.s3.amazonaws.com/ and "
        "https://assets.s3.eu-west-1.amazonaws.com/x.png and "
        "https://acct.blob.core.windows.net/container and "
        "https://storage.googleapis.com/gcs-bucket/file"
    )
    buckets = CloudModule()._extract_buckets(corpus)
    providers = {p for p, _ in buckets}
    assert "AWS S3" in providers
    assert "Azure Blob" in providers
    assert "Google Cloud Storage" in providers


def test_waf_fingerprint_detects_cloudflare():
    from allscan.waf import WafModule

    ctx = _make_ctx()
    out = WafModule()._fingerprint(ctx, {"Server": "cloudflare", "CF-RAY": "abc123"})
    assert any("Cloudflare" in f.title for f in out)


def test_fingerprint_cms_detects_wordpress_version():
    from allscan.fingerprint import FingerprintModule

    ctx = _make_ctx()
    body = '<meta name="generator" content="WordPress 5.8.1" /> /wp-content/ wp-json'
    out = FingerprintModule()._cms(ctx, "https://example.test", "", body)
    assert any("WordPress" in f.title and "5.8.1" in f.title for f in out)
    # version-bearing CMS feeds CVE correlation
    assert any(s["product"] == "WordPress" and s["version"] == "5.8.1"
               for s in ctx.state.get("services", []))


def test_report_includes_compliance_section():
    r = ScanResult(target="example.test")
    r.add(Finding(category=Category.HEADER, title="Missing content-security-policy header"))
    r.meta = {"compliance": [
        {"id": "hdr_csp", "name": "Content-Security-Policy",
         "baseline": "OWASP Secure Headers", "status": "fail", "detail": "Header missing."},
        {"id": "tls_chain", "name": "Valid certificate chain",
         "baseline": "TLS hygiene", "status": "pass", "detail": "OK."},
    ]}
    md = report.to_markdown(r)
    html = report.to_html(r)
    assert "Compliance Checklist" in md and "Content-Security-Policy" in md
    assert "compliance checklist" in html and "FAIL" in html


# --------------------------------------------------------------------------- #
# active probing + scope enforcement (offline)
# --------------------------------------------------------------------------- #


def test_scope_guard_in_out_and_deny():
    from allscan.scope import ScopeGuard

    g = ScopeGuard("10.0.0.5", allow=["10.0.1.0/24", "app.example.com"],
                   deny=["10.0.1.9"])
    assert g.check("10.0.0.5") is True            # the target itself
    assert g.check("10.0.1.50") is True           # allow CIDR
    assert g.check("10.0.1.9") is False           # denylist wins over allow CIDR
    assert g.check("app.example.com") is True     # allow host (exact)
    assert g.check("sub.app.example.com") is True # subdomain of allowed domain
    assert g.check("8.8.8.8") is False            # out of scope
    assert g.check("evil.com") is False           # out of scope
    d = g.decide("8.8.8.8")
    assert d.allowed is False and "out of scope" in d.reason


def test_scope_guard_production_heuristic():
    from allscan.scope import ScopeGuard

    assert ScopeGuard("127.0.0.1").looks_production() is False
    assert ScopeGuard("lab.test").looks_production() is False  # lab suffix


def test_active_module_gated_off_by_default():
    from allscan.active import ActiveModule

    ctx = _make_ctx()  # Config() => active is False
    assert ctx.config.active is False
    out = ActiveModule().run(ctx)
    assert len(out) == 1
    assert out[0].category == Category.ACTIVE
    assert "disabled" in out[0].title.lower()


def test_active_finding_schema_roundtrip():
    from allscan.active import ActiveModule

    f = ActiveModule()._finding(
        "reflected-input", "http://x/?a=1 [param=a]", Severity.LOW,
        evidence={"param": "a"}, confidence="medium",
        title="Reflected input observed", description="benign marker reflected",
    )
    assert f.category == Category.ACTIVE
    assert f.location.startswith("http://x")
    assert f.target == "http://x/?a=1"
    assert f.confidence == "medium"
    assert f.note == "manual validation required"
    assert f.evidence["type"] == "reflected-input"
    # the schema fields survive JSON round-trip
    back = Finding.from_dict(f.to_dict())
    assert back.location == f.location
    assert back.confidence == "medium"
    assert back.note == "manual validation required"


def test_config_active_defaults_off_and_cli_enables():
    from allscan.main import build_parser, config_from_args

    cfg = config_from_args(build_parser().parse_args(["example.test"]))
    assert cfg.active is False
    cfg2 = config_from_args(build_parser().parse_args(
        ["example.test", "--active", "--scope-allow", "a.com,10.0.0.0/24",
         "--scope-deny", "secret.example.com"]))
    assert cfg2.active is True
    assert "a.com" in cfg2.scope_allow and "10.0.0.0/24" in cfg2.scope_allow
    assert "secret.example.com" in cfg2.scope_deny


# --------------------------------------------------------------------------- #
# phase-4 small additions: skip flags, multi-target, CVE source, exploit refs, PDF
# --------------------------------------------------------------------------- #


def test_skip_flags_subtract_from_full_chain():
    from allscan.main import build_parser, config_from_args

    cfg = config_from_args(build_parser().parse_args(
        ["example.test", "--all", "--skip-web", "--skip", "active,cloud"]))
    assert "web" not in cfg.modules
    assert "active" not in cfg.modules
    assert "cloud" not in cfg.modules
    assert "recon" in cfg.modules  # untouched modules remain


def test_cve_source_flag_parsed():
    from allscan.main import build_parser, config_from_args

    cfg = config_from_args(build_parser().parse_args(
        ["example.test", "--cve-source", "circl"]))
    assert cfg.cve_sources == ["circl"]


def test_read_targets_file_hosts_and_cidr(tmp_path):
    from allscan.main import read_targets_file

    f = tmp_path / "targets.txt"
    f.write_text("# comment\nexample.com\n10.0.0.0/30\n\nbad target\n8.8.8.8\n")
    targets = read_targets_file(str(f), cap=100)
    assert "example.com" in targets
    assert "8.8.8.8" in targets
    # /30 expands to 2 usable hosts
    assert "10.0.0.1" in targets and "10.0.0.2" in targets
    assert "bad target" not in targets


def test_read_targets_file_respects_cap(tmp_path):
    from allscan.main import read_targets_file

    f = tmp_path / "t.txt"
    f.write_text("10.0.0.0/24\n")
    assert len(read_targets_file(str(f), cap=5)) == 5


def test_save_aggregate(tmp_path):
    r1 = ScanResult(target="a.test")
    r1.add(Finding(category=Category.CVE, title="CVE-1", severity=Severity.HIGH))
    r1.finished_at = r1.started_at + 1
    r2 = ScanResult(target="b.test")
    r2.finished_at = r2.started_at + 1
    path = report.save_aggregate([("a.test", r1), ("b.test", r2)], tmp_path)
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["targets"] == 2
    assert data["severity_totals"]["high"] == 1
    assert path.with_suffix(".md").exists()


def test_exploitrefs_enriches_with_kev_epss(monkeypatch):
    import allscan.exploitrefs as er
    from allscan.exploitrefs import ExploitRefsModule

    # avoid network: stub the feeds
    monkeypatch.setattr(ExploitRefsModule, "_load_kev",
                        lambda self, ctx: {"CVE-2021-44228"})
    monkeypatch.setattr(ExploitRefsModule, "_load_epss",
                        lambda self, ctx, ids: {"CVE-2021-44228": {"epss": 0.97, "percentile": 0.99}})
    monkeypatch.setattr(ExploitRefsModule, "_load_exploitdb_csv",
                        lambda self, ctx: {"CVE-2021-44228": ["50592"]})

    result = ScanResult(target="x.test")
    result.add(Finding(category=Category.CVE, title="CVE-2021-44228 — log4j 2.14",
                       severity=Severity.HIGH,
                       evidence={"cve_id": "CVE-2021-44228", "product": "log4j",
                                 "version": "2.14"}))
    ctx = _make_ctx(state={"_result": result})
    out = ExploitRefsModule().run(ctx)
    assert len(out) == 1
    f = out[0]
    assert f.category == Category.EXPLOITREF
    assert f.evidence["kev"] is True
    assert f.evidence["epss"] == 0.97
    assert f.evidence["references"]["exploitdb_ids"] == ["50592"]
    assert "no exploit code" in f.note
    # KEV => escalated priority
    assert f.severity is Severity.HIGH


def test_pdf_report_generates(tmp_path):
    pytest.importorskip("reportlab")
    from allscan import report_pdf

    r = ScanResult(target="pdf.test")
    r.add(Finding(category=Category.CVE, title="CVE-1 big bad",
                  severity=Severity.HIGH, location="svc/1.0"))
    r.add(Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.MEDIUM))
    r.meta = {"compliance": [{"id": "x", "name": "CSP", "baseline": "OWASP",
                              "status": "fail", "detail": "missing"}]}
    r.finished_at = r.started_at + 2
    path = report_pdf.save_pdf(r, tmp_path)
    assert path.exists() and path.suffix == ".pdf"
    assert path.read_bytes()[:4] == b"%PDF"


# --------------------------------------------------------------------------- #
# phase 2: recon depth (whois / asn / certs / surface) — offline
# --------------------------------------------------------------------------- #


def test_whois_date_flags_expiring_and_recent():
    import datetime
    from allscan.whois_rdap import WhoisModule, _parse_dt

    assert _parse_dt("2020-01-02T00:00:00Z") is not None
    ctx = _make_ctx(target="x.test")
    now = datetime.datetime.now(datetime.timezone.utc)
    soon = (now + datetime.timedelta(days=5)).isoformat()
    recent = (now - datetime.timedelta(days=10)).isoformat()
    flags = WhoisModule()._date_flags(ctx, recent, soon)
    titles = " ".join(f.title.lower() for f in flags)
    assert "expires in" in titles
    assert "recently registered" in titles


def test_asn_lookup_ip_parses_cymru(monkeypatch):
    from allscan.asn import AsnModule

    m = AsnModule()
    # stub the DNS TXT call: origin lookup returns Cymru-format string
    monkeypatch.setattr(AsnModule, "_txt",
                        lambda self, ctx, resolver, name: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01")
    ctx = _make_ctx()
    info = m._lookup_ip(ctx, None, "8.8.8.8")
    assert info["asn"] == "15169"
    assert info["prefix"] == "8.8.8.0/24"


def test_certs_ct_diff_baseline_then_new(tmp_path):
    from allscan.certs import CertsModule

    ctx = _make_ctx(target="x.test")
    ctx.config.output_dir = str(tmp_path)
    m = CertsModule()
    # first run: saves baseline, no diff finding
    first = m._ct_diff(ctx, {"1", "2"})
    assert first == []
    # second run with a new cert id: flags it
    second = m._ct_diff(ctx, {"1", "2", "3"})
    assert any("new certificate" in f.title.lower() for f in second)
    assert second[0].evidence["new_count"] == 1


def test_surface_maps_and_flags_third_party():
    from allscan.surface import SurfaceModule

    result = ScanResult(target="x.test")
    # two IPs under two different ASNs; one host each
    result.add(Finding(category=Category.ASN, title="AS111", evidence={
        "asn": "111", "org": "Primary", "ips": ["10.0.0.1", "10.0.0.2"], "prefixes": ["10.0.0.0/24"]}))
    result.add(Finding(category=Category.ASN, title="AS222", evidence={
        "asn": "222", "org": "CDN", "ips": ["9.9.9.9"], "prefixes": ["9.9.9.0/24"]}))
    state = {
        "_result": result,
        "hosts": {"a.x.test": ["10.0.0.1"], "b.x.test": ["10.0.0.2"], "cdn.x.test": ["9.9.9.9"]},
        "services": [{"host": "a.x.test", "port": 443, "product": "nginx", "version": "1.18"}],
        "web_hosts": ["https://a.x.test"],
    }
    ctx = _make_ctx(target="x.test", state=state)
    out = SurfaceModule().run(ctx)
    assert ctx.state.get("surface")
    assert any(f.category == Category.SURFACE and "Attack surface" in f.title for f in out)
    # cdn.x.test is on AS222 (not the primary AS111) -> third-party flag
    assert any("third-party ASNs" in f.title for f in out)


# --------------------------------------------------------------------------- #
# phase 3: more active checks + scanner integrations — offline
# --------------------------------------------------------------------------- #


def test_active_jwt_analysis_flags_alg_none():
    import base64
    from allscan.active import ActiveModule

    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    token = f"{header}.eyJzdWIiOiIxMjMifQ.sig"
    state = {"pages": {"https://x.test": {"body": f"var t='{token}'", "headers": {}, "cookies": []}}}
    ctx = _make_ctx(target="x.test", state=state)
    out = ActiveModule()._check_jwt(ctx)
    assert any(f.evidence.get("type") == "jwt-analysis" for f in out)
    f = out[0]
    assert f.severity is Severity.HIGH  # alg=none
    assert any("alg=none" in i for i in f.evidence["issues"])


def test_integrations_parse_httpx_and_nuclei():
    from allscan.integrations import parse_httpx, parse_nuclei
    from allscan.models import Finding as F

    emit = lambda **kw: F(**{**kw, "module": "integrations"})
    httpx = '{"url":"https://x.test","status_code":200,"title":"Home","tech":["nginx"]}'
    fh = parse_httpx(httpx + "\nnot-json\n", emit)
    assert len(fh) == 1 and fh[0].category == Category.WEB and fh[0].evidence["status"] == 200

    nuclei = ('{"template-id":"CVE-2021-1","info":{"name":"Thing","severity":"high",'
              '"description":"d","tags":["cve"]},"matched-at":"https://x.test/a"}')
    fn = parse_nuclei(nuclei, emit)
    assert len(fn) == 1
    assert fn[0].severity is Severity.HIGH
    assert fn[0].note == "manual validation required"
    assert fn[0].category == Category.ACTIVE


def test_integrations_parse_sqlmap_detection_only():
    from allscan.integrations import parse_sqlmap
    from allscan.models import Finding as F

    emit = lambda **kw: F(**{**kw, "module": "integrations"})
    log = "sqlmap ... Parameter 'id' is vulnerable. Do you want to keep testing?"
    out = parse_sqlmap(log, "http://x.test/p?id=1", emit)
    assert len(out) == 1
    assert out[0].severity is Severity.HIGH
    assert out[0].evidence["phase"] == "detection"
    assert "no data extraction" in out[0].description.lower()
    # clean log => nothing
    assert parse_sqlmap("all tested, not injectable", "http://x/p?id=1", emit) == []


def test_integrations_parse_masscan():
    from allscan.integrations import parse_masscan
    from allscan.models import Finding as F

    emit = lambda **kw: F(**{**kw, "module": "integrations"})
    data = '[{"ip":"10.0.0.1","ports":[{"port":22,"proto":"tcp"}]}]'
    out = parse_masscan(data, emit)
    assert len(out) == 1 and out[0].evidence["port"] == 22 and out[0].category == Category.PORT


def test_integrations_gating(monkeypatch):
    import allscan.integrations as integ
    from allscan.integrations import IntegrationsModule

    # unknown tool -> skipped, no crash
    ctx = _make_ctx()
    ctx.config.integrations = ["bogus"]
    out = IntegrationsModule().run(ctx)
    assert any("Unknown" in (f.description or "") or "bogus" in f.title for f in out) or out == []

    # active tool present on PATH but --active OFF -> skipped with that reason
    monkeypatch.setattr(integ.shutil, "which", lambda name: "/usr/bin/" + name)
    ctx2 = _make_ctx()
    ctx2.config.integrations = ["nuclei"]
    ctx2.config.active = False
    out2 = IntegrationsModule().run(ctx2)
    assert any("requires --active" in (f.description or "") for f in out2)


# --------------------------------------------------------------------------- #
# phase 5: engagement platform (projects / evidence / ledger / retest)
# --------------------------------------------------------------------------- #


def test_platform_project_scope_window_and_auth(tmp_path):
    from allscan.platform import ProjectStore

    st = ProjectStore(str(tmp_path))
    p = st.create("acme", "ACME")
    p.set_scope(allow=["app.acme.test"], deny=["prod.acme.test"])
    p.set_window("2020-01-01", "2020-01-02")  # in the past
    assert p.within_window() is False
    authf = tmp_path / "auth.txt"
    authf.write_text("authorized")
    rec = p.add_authorization(str(authf))
    assert len(rec["sha256"]) == 64 and p.has_authorization
    assert p.data["scope"]["allow"] == ["app.acme.test"]


def test_platform_evidence_chain_of_custody_detects_tamper(tmp_path):
    from allscan.platform import ProjectStore

    st = ProjectStore(str(tmp_path))
    p = st.create("e")
    f = tmp_path / "shot.txt"
    f.write_text("original")
    rec = p.add_evidence(str(f), "note")
    assert p.verify_evidence()[0]["intact"] is True
    # tamper with the STORED copy -> verify must flag it
    Path(rec["stored_path"]).write_text("tampered!")
    assert p.verify_evidence()[0]["intact"] is False


def test_platform_ledger_dedup_status_and_fingerprint_stable():
    from allscan.platform import ProjectStore, fingerprint

    f1 = Finding(category=Category.CVE, title="CVE-1", severity=Severity.HIGH)
    f2 = Finding(category=Category.CVE, title="CVE-1", severity=Severity.HIGH)
    assert fingerprint(f1) == fingerprint(f2)  # stable across instances

    import tempfile
    st = ProjectStore(tempfile.mkdtemp())
    p = st.create("l")
    r = ScanResult(target="x.test")
    r.add(f1)
    r.add(Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.MEDIUM))
    info = p.ingest_run(r)
    assert info["new"] == 2
    # ingesting the same findings again dedups (0 new)
    info2 = p.ingest_run(r)
    assert info2["new"] == 0 and info2["updated"] == 2
    fp = fingerprint(f1)
    p.set_finding_status(fp, "confirmed", "verified")
    assert p.data["findings"][fp]["status"] == "confirmed"


def test_platform_retest_fixed_notfixed_regression():
    import tempfile
    from allscan.platform import ProjectStore, fingerprint

    st = ProjectStore(tempfile.mkdtemp())
    p = st.create("r")
    base = ScanResult(target="x.test")
    csp = Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.MEDIUM)
    cve = Finding(category=Category.CVE, title="CVE-9", severity=Severity.HIGH)
    base.add(csp)
    base.add(cve)
    p.ingest_run(base)

    # retest: CSP fixed (absent), CVE-9 still present
    rt = ScanResult(target="x.test")
    rt.add(Finding(category=Category.CVE, title="CVE-9", severity=Severity.HIGH))
    rep = p.retest(rt)
    assert rep["counts"]["fixed"] == 1 and rep["counts"]["not_fixed"] == 1
    assert p.data["findings"][fingerprint(csp)]["status"] == "fixed"

    # a later run where CSP reappears => regression
    back = ScanResult(target="x.test")
    back.add(Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.MEDIUM))
    p.ingest_run(back)
    assert p.data["findings"][fingerprint(csp)]["status"] == "regression"


# --------------------------------------------------------------------------- #
# phase 6: threat-model/compliance mapping + topology + report sections
# --------------------------------------------------------------------------- #


def test_mapping_attack_stride_compliance():
    from allscan import mapping

    sqli = Finding(category=Category.ACTIVE, title="injectable", severity=Severity.HIGH,
                   evidence={"type": "sql-injection"})
    a = mapping.attack(sqli)
    assert a["technique_id"] == "T1190" and a["tactic"] == "Initial Access"
    assert "Tampering" in mapping.stride(sqli)
    refs = mapping.compliance_refs(sqli)
    assert refs["owasp"].startswith("A03") and refs["cwe"] == "CWE-89"

    hdr = Finding(category=Category.HEADER, title="Missing content-security-policy header")
    assert mapping.compliance_refs(hdr)["cwe"] == "CWE-693"


def test_mapping_likelihood_and_risk_matrix():
    from allscan import mapping

    kev = Finding(category=Category.EXPLOITREF, title="CVE-x", severity=Severity.HIGH,
                  evidence={"kev": True})
    assert mapping.likelihood(kev) == "high"
    low = Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.LOW)
    assert mapping.likelihood(low) == "low"
    m = mapping.risk_matrix([kev, low])
    assert m["high"]["high"] == 1
    assert m["low"]["low"] == 1


def test_threatmodel_module_stashes_meta():
    from allscan.threatmodel import ThreatModelModule

    result = ScanResult(target="x.test")
    result.add(Finding(category=Category.ACTIVE, title="injectable", severity=Severity.HIGH,
                       evidence={"type": "sql-injection"}))
    result.add(Finding(category=Category.TLS, title="Weak cipher negotiated", severity=Severity.HIGH))
    ctx = _make_ctx(state={"_result": result})
    out = ThreatModelModule().run(ctx)
    assert out and "ATT&CK" in out[0].title
    assert ctx.state["risk_matrix"]["high"]  # populated
    tm = ctx.state["threatmodel"]
    assert any(t["technique_id"] == "T1190" for t in tm["attack_techniques"])
    assert "compliance_frameworks" in tm


def test_topology_svg_from_surface():
    from allscan import report

    surface = {"nodes": [{"id": "a.x.test", "type": "host"},
                         {"id": "10.0.0.1", "type": "ip"},
                         {"id": "AS111", "type": "asn"}],
               "edges": [{"from": "a.x.test", "to": "10.0.0.1", "kind": "resolves_to"},
                         {"from": "10.0.0.1", "to": "AS111", "kind": "announced_by"}]}
    svg = report.topology_svg(surface)
    assert svg.startswith("<svg") and "a.x.test" in svg and "<line" in svg
    assert report.topology_svg({}) == ""  # empty surface -> no svg


def test_report_has_risk_matrix_and_mapping_sections():
    from allscan import report

    r = ScanResult(target="x.test")
    r.add(Finding(category=Category.ACTIVE, title="injectable", severity=Severity.HIGH,
                  evidence={"type": "sql-injection"}))
    r.meta = {
        "risk_matrix": {"high": {"high": 1, "medium": 0, "low": 0},
                        "medium": {"high": 0, "medium": 0, "low": 0},
                        "low": {"high": 0, "medium": 0, "low": 0},
                        "info": {"high": 0, "medium": 0, "low": 0}},
        "threatmodel": {"attack_techniques": [{"technique_id": "T1190",
                        "technique": "Exploit Public-Facing Application",
                        "tactic": "Initial Access", "count": 1}],
                        "stride": {"Tampering": 1},
                        "compliance_frameworks": {"owasp": ["A03:2021 Injection"]}},
        "surface": {"nodes": [{"id": "x.test", "type": "host"}], "edges": []},
    }
    md = report.to_markdown(r)
    html = report.to_html(r)
    assert "Risk Matrix" in md and "T1190" in md and "A03:2021" in md
    assert "risk matrix" in html and "T1190" in html and "attack-surface topology" in html


# --------------------------------------------------------------------------- #
# phase 4 completion: CPE, vuln-age, business-impact scoring, FP suppression
# --------------------------------------------------------------------------- #


def test_vulnintel_cpe_age_and_scoring_helpers():
    from allscan.vulnintel import make_cpe, cve_age_years, risk_score

    assert make_cpe("nginx", "1.18.0") == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    assert make_cpe("Apache HTTP", "") .endswith(":*:*:*:*:*:*:*")
    assert cve_age_years("CVE-2015-1000") >= 9
    assert cve_age_years("not-a-cve") is None
    assert risk_score("high", "high", "critical") == (100, "Critical")
    assert risk_score("low", "low", "low")[1] == "Low"


def test_vulnintel_module_scores_and_suppresses():
    from allscan.vulnintel import VulnIntelModule
    from allscan.platform import fingerprint

    result = ScanResult(target="api.corp.test")
    cve = Finding(category=Category.CVE, title="CVE-2021-44228 log4j", severity=Severity.HIGH,
                  target="api.corp.test",
                  evidence={"cve_id": "CVE-2021-44228", "product": "log4j",
                            "version": "2.14", "kev": True})
    noise = Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.LOW)
    result.add(cve)
    result.add(noise)

    ctx = _make_ctx(target="api.corp.test",
                    state={"_result": result})
    ctx.config.asset_criticality = {"api.corp.test": "critical"}
    ctx.config.suppress_fingerprints = [fingerprint(noise)]
    out = VulnIntelModule().run(ctx)

    # CPE + age annotated on the CVE
    assert cve.evidence["cpe"].startswith("cpe:2.3:a:log4j:log4j:2.14")
    assert cve.evidence["age_years"] >= 3
    # scored with critical asset + KEV => high score, and present in top risks
    assert cve.evidence["risk_score"] >= 60 and cve.evidence["risk_band"] == "Critical"
    top = ctx.state["top_risks"]
    assert any(t["fingerprint"] == fingerprint(cve) for t in top)
    # the suppressed finding is marked and excluded from top risks
    assert noise.evidence.get("suppressed") is True
    assert all(t["fingerprint"] != fingerprint(noise) for t in top)
    # aging high-risk KEV CVE produces its own flag
    assert any("Aging high-risk" in f.title for f in out)


def test_report_top_risks_section():
    from allscan import report

    r = ScanResult(target="x.test")
    r.add(Finding(category=Category.CVE, title="CVE-1", severity=Severity.HIGH))
    r.meta = {"top_risks": [{"fingerprint": "abc", "title": "CVE-1 big",
                             "category": "cves", "severity": "high",
                             "likelihood": "high", "criticality": "critical",
                             "risk_score": 100, "risk_band": "Critical", "target": "x.test"}]}
    assert "Top Risks" in report.to_markdown(r)
    assert "top risks" in report.to_html(r)


# --------------------------------------------------------------------------- #
# Discord webhook delivery
# --------------------------------------------------------------------------- #


def test_http_helper_applies_proxy_headers_and_scope_gated_auth(monkeypatch):
    import allscan.base as base_mod
    from allscan.scope import ScopeGuard

    captured = {}

    class Resp:
        status_code = 200
        text = ""
        headers: dict = {}

    def fake_request(method, url, **kw):
        captured["url"] = url
        captured["kw"] = kw
        return Resp()

    monkeypatch.setattr(base_mod.requests, "request", fake_request)

    cfg = Config(rate_limit=0, user_agent="UA-X", proxy="http://127.0.0.1:8080",
                 extra_headers={"X-Bb": "h1"}, cookie="s=1", auth_bearer="TK")
    ctx = _make_ctx(target="10.0.0.5", state={})
    ctx.config = cfg
    ctx.scope = ScopeGuard("10.0.0.5")

    # in-scope host -> UA override + proxy + secrets attached
    ctx.http_get("http://10.0.0.5/app")
    h = captured["kw"]["headers"]
    assert h["User-Agent"] == "UA-X"
    assert h["X-Bb"] == "h1" and h["Cookie"] == "s=1"
    assert h["Authorization"] == "Bearer TK"
    assert captured["kw"]["proxies"] == {"http": "http://127.0.0.1:8080",
                                         "https": "http://127.0.0.1:8080"}

    # out-of-scope host (crt.sh-style enrichment) -> UA + proxy, NO secrets
    ctx.http_get("https://crt.sh/?q=x")
    h2 = captured["kw"]["headers"]
    assert h2["User-Agent"] == "UA-X"
    assert "X-Bb" not in h2 and "Cookie" not in h2 and "Authorization" not in h2
    assert "proxies" in captured["kw"]


def test_resource_path_frozen_and_source(monkeypatch):
    from allscan.utils import resource_path

    # source mode: resolves next to the package root
    p = resource_path("config.example.yaml")
    assert p.name == "config.example.yaml" and p.exists()

    # frozen mode: resolves under sys._MEIPASS
    monkeypatch.setattr(sys, "_MEIPASS", "/tmp/meipass_test", raising=False)
    fp = resource_path("config.example.yaml")
    assert str(fp) == str(Path("/tmp/meipass_test") / "config.example.yaml")


def test_config_to_audit_dict_masks_secrets():
    cfg = Config(cookie="s=1", auth_bearer="TK", proxy="http://p",
                 discord_webhook="https://discord.com/api/webhooks/1/x",
                 nvd_api_key="KEY")
    d = cfg.to_audit_dict()
    for key in ("cookie", "auth_bearer", "proxy", "discord_webhook", "nvd_api_key"):
        assert d[key] == "***"


def test_notify_webhook_validation_and_payload():
    from allscan import notify

    assert notify.looks_like_webhook("https://discord.com/api/webhooks/123/abcDEF-ghi")
    assert notify.looks_like_webhook("https://ptb.discord.com/api/webhooks/9/xy_z")
    assert not notify.looks_like_webhook("https://evil.example.com/api/webhooks/1/x")
    assert not notify.looks_like_webhook("")

    from allscan import __version__
    r = ScanResult(target="x.test")
    r.modules_run = ["vulns", "headers"]
    r.add(Finding(category=Category.CVE, title="c", severity=Severity.HIGH, module="vulns"))
    r.finished_at = r.started_at + 1
    payload = notify.build_payload(r)
    embed = payload["embeds"][0]
    assert payload["username"] == "RECON RESULTS"
    assert embed["title"] == f"All Scan v{__version__}"
    assert "x.test" in embed["description"]
    assert embed["color"] == 0xE5484D  # high => red
    assert embed["footer"]["text"] == "Copyrights to @i2w23192"
    # one field per module that ran; the vulns module shows its finding
    names = [f["name"] for f in embed["fields"]]
    assert len(embed["fields"]) == 2
    assert any("CVE Correlation" == n for n in names)
    assert any("1 finding" in f["value"] for f in embed["fields"] if f["name"] == "CVE Correlation")


def test_notify_attachments_pick_json_html_and_skip_oversize(tmp_path):
    from allscan import notify

    (tmp_path / "r.json").write_text("{}")
    (tmp_path / "r.html").write_text("<html></html>")
    (tmp_path / "r.md").write_text("# md")
    big = tmp_path / "big.html"
    big.write_bytes(b"x" * (notify.MAX_ATTACH_BYTES + 10))
    parts, skipped = notify._attachments(
        [tmp_path / "r.json", tmp_path / "r.html", tmp_path / "r.md", big])
    names = [p[1][0] for p in parts]
    assert "r.json" in names and "r.html" in names and "r.md" not in names
    assert any("big.html" in s for s in skipped)  # oversize skipped


def test_notify_send_discord_posts_multipart(monkeypatch, tmp_path):
    from allscan import notify

    captured = {}

    class Resp:
        status_code = 204

    def fake_post(url, files=None, timeout=None):
        captured["url"] = url
        captured["fields"] = [f[0] for f in files]
        return Resp()

    monkeypatch.setattr(notify.requests, "post", fake_post)
    jp = tmp_path / "r.json"; jp.write_text("{}")
    hp = tmp_path / "r.html"; hp.write_text("<html></html>")
    r = ScanResult(target="x.test")
    ok, msg = notify.send_discord("https://discord.com/api/webhooks/1/abc", r, [jp, hp])
    assert ok and "sent 2" in msg
    assert "payload_json" in captured["fields"]
    assert captured["fields"].count("files[0]") == 1 and "files[1]" in captured["fields"]


def test_notify_deliver_noop_without_webhook():
    from allscan import notify

    assert notify.deliver(ScanResult(target="x.test"), Config(), []) is None


def test_notify_send_discord_embed_only_when_no_files(monkeypatch):
    from allscan import notify

    captured = {}

    class Resp:
        status_code = 204

    def fake_post(url, **kw):
        captured["kw"] = kw
        return Resp()

    monkeypatch.setattr(notify.requests, "post", fake_post)
    r = ScanResult(target="x.test")
    # no attachable files -> still sends the summary embed (data, not files)
    ok, msg = notify.send_discord("https://discord.com/api/webhooks/1/x", r, [])
    assert ok and "summary" in msg
    assert "data" in captured["kw"] and "files" not in captured["kw"]


def test_notify_deliver_regenerates_reports_when_missing(monkeypatch):
    from allscan import notify

    captured = {}

    class Resp:
        status_code = 204

    def fake_post(url, **kw):
        captured["kw"] = kw
        return Resp()

    monkeypatch.setattr(notify.requests, "post", fake_post)
    cfg = Config(discord_webhook="https://discord.com/api/webhooks/1/x")
    r = ScanResult(target="x.test")
    r.add(Finding(category=Category.HEADER, title="Missing CSP", severity=Severity.MEDIUM))
    # paths empty -> deliver regenerates json+html and attaches them
    msg = notify.deliver(r, cfg, [])
    assert msg.startswith("Discord:")
    assert "files" in captured["kw"]


def test_tui_finished_saves_all_report_formats(tmp_path, monkeypatch):
    """Regression: the TUI must auto-save MD + HTML (+JSON), not JSON alone."""
    import asyncio
    from allscan.tui import AllscanApp, ScanScreen, ResultsScreen

    # stub the engine registry so no network runs
    import allscan.engine as engine_mod
    monkeypatch.setattr(engine_mod, "get_registry", lambda: {"recon": StubRecon()})

    async def drive():
        cfg = Config(modules=["recon"], rate_limit=0, output_dir=str(tmp_path))
        app = AllscanApp(initial_target="example.test", config=cfg)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.target = "example.test"
            app.authorized = True
            app.push_screen(ScanScreen())
            for _ in range(50):
                await pilot.pause(0.1)
                if isinstance(app.screen, ResultsScreen):
                    break
            assert isinstance(app.screen, ResultsScreen)

    asyncio.run(drive())
    exts = {p.suffix for p in tmp_path.glob("allscan_*")}
    assert ".json" in exts and ".md" in exts and ".html" in exts


def test_tui_allscan_runs_all_modules_and_skips_config():
    """Pressing Allscan confirms target+auth once then jumps straight to the
    live scan with every module selected, bypassing checklist + settings."""
    import asyncio

    from allscan.engine import MODULE_ORDER
    from allscan.tui import AllscanApp, ScanScreen, WelcomeScreen

    async def drive():
        # start with a deliberately narrow module set to prove Allscan overrides it
        cfg = Config(modules=["web"])
        app = AllscanApp(initial_target="example.test", config=cfg)
        async with app.run_test(size=(140, 45)) as pilot:
            await pilot.pause()
            screen = app.screen
            # without authorization, Allscan must be blocked
            screen.query_one("#auth-check").value = False
            screen.action_allscan()
            await pilot.pause()
            assert isinstance(app.screen, WelcomeScreen)
            # authorize -> Allscan jumps straight to the scan with all modules
            screen.query_one("#auth-check").value = True
            await pilot.pause()
            screen.action_allscan()
            await pilot.pause()
            assert isinstance(app.screen, ScanScreen)
            assert app.config.modules == list(MODULE_ORDER)
            assert app.target == "example.test"
            # cancel immediately so no real network scan proceeds
            app.screen.action_stop()
            await pilot.pause()

    asyncio.run(drive())


# --------------------------------------------------------------------------- #
# Port/service scan enhancements
# --------------------------------------------------------------------------- #
def _scan_ctx(target="127.0.0.1", state=None, **cfg_kw):
    from allscan.base import ModuleContext
    from allscan.utils import AuditLog, CancelToken, RateLimiter
    return ModuleContext(
        target=target,
        config=Config(rate_limit=0, **cfg_kw),
        rate=RateLimiter(0),
        audit=AuditLog(None),
        cancel=CancelToken(),
        state=state if state is not None else {},
        _log=lambda m, msg: None,
        _on_finding=lambda f: None,
        _module_name="scan",
    )


def test_scan_port_tables_are_broad():
    from allscan.scan import COMMON_PORTS, SENSITIVE_PORTS
    # the enhancement widened coverage substantially
    assert len(COMMON_PORTS) > 150
    for p in (6379, 9200, 27017, 2375, 6443, 5900):
        assert p in SENSITIVE_PORTS


def test_parse_ports_handles_ranges_and_junk():
    from allscan.main import _parse_ports
    assert _parse_ports("8000, 8443 9000-9002, nope, 70000, -5") == [8000, 8443, 9000, 9001, 9002]


def test_fallback_scan_grabs_banner_and_version():
    import socket, threading, time
    from allscan.scan import ScanModule
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(5)
    port = srv.getsockname()[1]

    def serve():
        # the scanner connects twice: once to test the port is open, once to
        # grab the banner — serve several connections so both succeed.
        for _ in range(4):
            try:
                c, _ = srv.accept()
                try:
                    c.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
                except Exception:
                    pass
                time.sleep(0.02); c.close()
            except Exception:
                break
    threading.Thread(target=serve, daemon=True).start()
    try:
        ctx = _scan_ctx(skip_nmap=True, timeout=1.0, threads=8, extra_ports=[port])
        findings = ScanModule().run(ctx)
    finally:
        srv.close()
    titles = [f.title for f in findings]
    assert any(f"{port}/tcp open (OpenSSH 8.9p1)" in t for t in titles)
    svc = ctx.state["services"][0]
    assert svc["product"] == "OpenSSH" and svc["version"] == "8.9p1"


def test_probe_findings_flag_unauth_services():
    from allscan.scan import ScanModule
    ctx = _scan_ctx(state={"services": []})
    m = ScanModule()
    redis = m._probe_findings(ctx, "h", 6379, "+PONG", {})
    assert redis and redis[0].severity == Severity.HIGH
    noauth = m._probe_findings(ctx, "h", 6379, "-NOAUTH Authentication required.", {})
    assert noauth and noauth[0].severity == Severity.INFO
    memc = m._probe_findings(ctx, "h", 11211, "VERSION 1.6.9", {})
    assert memc and memc[0].severity == Severity.HIGH


def test_nmap_xml_parses_cpe_and_scripts():
    from allscan.scan import ScanModule
    xml = (
        '<nmaprun><host><ports><port protocol="tcp" portid="22">'
        '<state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1">'
        '<cpe>cpe:/a:openbsd:openssh:8.2p1</cpe></service>'
        '<script id="ssh-hostkey" output="2048 RSA"/></port></ports>'
        '<hostscript><script id="smb-os-discovery" output="OS: Windows"/></hostscript>'
        "</host></nmaprun>"
    )
    ctx = _scan_ctx(target="h", state={"services": []})
    findings = ScanModule()._parse_nmap_xml(ctx, "h", xml)
    assert any("smb-os-discovery" in f.title for f in findings)
    svc = ctx.state["services"][0]
    assert svc["cpe"] == ["cpe:/a:openbsd:openssh:8.2p1"]
    port_f = next(f for f in findings if "22/tcp open" in f.title)
    assert port_f.evidence.get("cpe") == ["cpe:/a:openbsd:openssh:8.2p1"]
    assert "ssh-hostkey" in port_f.evidence.get("scripts", {})


def test_nmap_command_reflects_intensity_options():
    import subprocess
    from allscan.scan import ScanModule
    captured = {}
    real = subprocess.run

    def fake(cmd, **kw):
        captured["cmd"] = cmd
        class R:
            stdout = ""
            stderr = ""
        return R()
    subprocess.run = fake
    try:
        ctx = _scan_ctx(target="h", scan_intensity="aggressive", scan_scripts=True,
                        udp_scan=True, top_ports=2000, os_detection=True)
        ScanModule()._nmap_scan(ctx, "h")
    finally:
        subprocess.run = real
    cmd = " ".join(captured["cmd"])
    for frag in ("--top-ports 2000", "--version-all", "--version-intensity 9",
                 "-sC", "-sU", "-O"):
        assert frag in cmd


def test_weak_tls_version_flagged_from_scan():
    from allscan.scan import ScanModule
    ctx = _scan_ctx(target="h", state={"services": []})
    fs = ScanModule()._record_port(ctx, "h", 443, "tcp", "https", "nginx", "1.18",
                                   tls={"tls_version": "TLSv1", "cipher": "AES"})
    assert any("obsolete TLSv1" in f.title and f.severity == Severity.MEDIUM for f in fs)


def test_zookeeper_probe_flags_unauth():
    from allscan.scan import ScanModule
    ctx = _scan_ctx(state={"services": []})
    m = ScanModule()
    findings = m._probe_findings(ctx, "h", 2181, "imok", {})
    assert findings and findings[0].severity == Severity.HIGH
    assert "2181" in findings[0].title
    # Non-imok response = not flagged
    assert m._probe_findings(ctx, "h", 2181, "error", {}) == []


def test_mongodb_probe_flags_accessible():
    from allscan.scan import ScanModule
    ctx = _scan_ctx(state={"services": []})
    m = ScanModule()
    # Craft a fake MongoDB OP_REPLY: bytes 12-15 = \x01\x00\x00\x00 (opCode=1)
    op_reply = (
        b"\x20\x00\x00\x00"  # messageLength
        b"\x01\x00\x00\x00"  # requestID
        b"\x01\x00\x00\x00"  # responseTo
        b"\x01\x00\x00\x00"  # opCode = 1 (OP_REPLY)
        b"\x00" * 16         # rest of response
    )
    banner = op_reply.decode("latin-1", "ignore")
    findings = m._probe_findings(ctx, "h", 27017, banner, {})
    assert findings and findings[0].severity == Severity.HIGH
    assert "MongoDB" in findings[0].title
    # Short/non-OP_REPLY banner = not flagged
    assert m._probe_findings(ctx, "h", 27017, "short", {}) == []


def test_tls_self_signed_flagged():
    from allscan.scan import ScanModule
    ctx = _scan_ctx(state={"services": []})
    fs = ScanModule()._record_port(
        ctx, "h", 443, "tcp", "https", "nginx", "1.18",
        tls={"tls_version": "TLSv1.3", "cipher": "AES256-GCM-SHA384",
             "self_signed": True, "cert_days_remaining": 300},
    )
    assert any("self-signed" in f.title.lower() for f in fs)
    self_f = next(f for f in fs if "self-signed" in f.title.lower())
    assert self_f.severity == Severity.MEDIUM


def test_tls_cert_expiry_flagged():
    from allscan.scan import ScanModule
    ctx = _scan_ctx(state={"services": []})
    m = ScanModule()
    # Expired cert
    fs = m._record_port(ctx, "h", 443, "tcp", "https", "", "",
                        tls={"tls_version": "TLSv1.3", "cert_days_remaining": -5})
    assert any("EXPIRED" in f.title and f.severity == Severity.HIGH for f in fs)
    # Expires in 10 days → HIGH
    fs2 = m._record_port(ctx, "h", 443, "tcp", "https", "", "",
                         tls={"tls_version": "TLSv1.3", "cert_days_remaining": 10})
    assert any("expires in 10 days" in f.title.lower() and f.severity == Severity.HIGH for f in fs2)
    # Expires in 25 days → MEDIUM
    fs3 = m._record_port(ctx, "h", 443, "tcp", "https", "", "",
                         tls={"tls_version": "TLSv1.3", "cert_days_remaining": 25})
    assert any("expires in 25 days" in f.title.lower() and f.severity == Severity.MEDIUM for f in fs3)
    # Far future (200 days) → no expiry finding
    fs4 = m._record_port(ctx, "h", 443, "tcp", "https", "", "",
                         tls={"tls_version": "TLSv1.3", "cert_days_remaining": 200})
    assert not any("expires" in f.title.lower() for f in fs4)


def test_weak_cipher_flagged_from_scan():
    from allscan.scan import ScanModule
    ctx = _scan_ctx(state={"services": []})
    m = ScanModule()
    for weak in ("RC4-SHA", "DES-CBC3-SHA", "EXP-RC4-MD5", "NULL-MD5"):
        fs = m._record_port(ctx, "h", 443, "tcp", "https", "", "",
                            tls={"tls_version": "TLSv1.2", "cipher": weak})
        assert any("weak tls cipher" in f.title.lower() and f.severity == Severity.HIGH
                   for f in fs), f"Expected weak-cipher finding for cipher={weak}"
    # Strong cipher = no weak-cipher finding
    fs_ok = m._record_port(ctx, "h", 443, "tcp", "https", "", "",
                           tls={"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"})
    assert not any("weak tls cipher" in f.title.lower() for f in fs_ok)


def test_http_api_probe_flags_elasticsearch():
    from allscan.scan import ScanModule

    ctx = _scan_ctx(state={"services": []})

    class FakeResp:
        status_code = 200
        text = '{"cluster_name":"my-cluster","version":{"number":"7.10.0"}}'

    ctx.http_get = lambda url, **kw: FakeResp()
    m = ScanModule()
    findings = m._http_api_probe_findings(ctx, "127.0.0.1", 9200, {"port": 9200})
    assert findings and findings[0].severity == Severity.HIGH
    assert "Elasticsearch" in findings[0].title
    assert "without authentication" in findings[0].title

    # Port not in _HTTP_APIS → empty
    assert m._http_api_probe_findings(ctx, "127.0.0.1", 1234, {}) == []

    # Non-200 response → empty
    class NotFound:
        status_code = 404
        text = ""
    ctx.http_get = lambda url, **kw: NotFound()
    assert m._http_api_probe_findings(ctx, "127.0.0.1", 9200, {}) == []

    # Body indicator not found → empty
    class WrongBody:
        status_code = 200
        text = '{"auth":"required"}'
    ctx.http_get = lambda url, **kw: WrongBody()
    assert m._http_api_probe_findings(ctx, "127.0.0.1", 9200, {}) == []


def test_http_api_probe_no_indicator_accepts_any_200():
    from allscan.scan import ScanModule

    ctx = _scan_ctx(state={"services": []})

    class OkResp:
        status_code = 200
        text = "leader-ip"

    ctx.http_get = lambda url, **kw: OkResp()
    # Consul (8500) has empty indicator — any 200 is a hit
    findings = ScanModule()._http_api_probe_findings(ctx, "127.0.0.1", 8500, {})
    assert findings and "Consul" in findings[0].title


def test_http_api_probe_handles_exception_gracefully():
    from allscan.scan import ScanModule

    ctx = _scan_ctx(state={"services": []})
    ctx.http_get = lambda url, **kw: (_ for _ in ()).throw(ConnectionRefusedError())
    findings = ScanModule()._http_api_probe_findings(ctx, "127.0.0.1", 9200, {})
    assert findings == []


def test_guess_version_covers_extended_products():
    from allscan.scan import _guess_version
    assert _guess_version("Server: Envoy/1.26.0") == ("Envoy", "1.26.0")
    assert _guess_version("X-Powered-By: Traefik/2.9.6") == ("Traefik", "2.9.6")
    assert _guess_version("Server: Caddy/2.6.4") == ("Caddy", "2.6.4")
    assert _guess_version("server: uvicorn/0.21.1") == ("uvicorn", "0.21.1")


# --------------------------------------------------------------------------- #
# intensity profiles, deeper active checks, and branding (offline / localhost)
# --------------------------------------------------------------------------- #


def test_credit_shown_in_tui_cli_and_menu(capsys):
    import allscan
    from allscan import main as main_mod

    assert allscan.CREDIT == "Made by @i2w / 1337 Group"
    main_mod.print_banner()
    assert "Made by @i2w / 1337 Group" in capsys.readouterr().out
    menu_src = (Path(__file__).resolve().parent.parent / "menu.py").read_text()
    assert "CREDIT" in menu_src

    pytest.importorskip("textual")
    import asyncio
    from allscan.tui import AllscanApp

    async def run():
        app = AllscanApp(initial_target=None, config=Config())
        async with app.run_test(size=(110, 50)) as pilot:
            await pilot.pause()
            text = "".join(seg.text for strip in app.screen._compositor.render_strips()
                           for seg in strip)
            return allscan.CREDIT in text, allscan.CREDIT in app.sub_title

    on_welcome, in_header = asyncio.run(run())
    assert on_welcome and in_header


def test_intensity_config_profiles_and_cli():
    from allscan.config import INTENSITY_PROFILES
    from allscan.main import build_parser, config_from_args

    assert Config().intensity == "standard"
    assert Config().profile() is INTENSITY_PROFILES["standard"]
    cfg = config_from_args(build_parser().parse_args(["x.test", "--intensity", "max"]))
    assert cfg.intensity == "max" and cfg.profile()["max_checks"] is True
    # unknown values degrade to standard instead of crashing
    assert Config(intensity="bogus").profile() is INTENSITY_PROFILES["standard"]
    # higher levels strictly widen coverage
    p = INTENSITY_PROFILES
    assert p["standard"]["urls"] < p["deep"]["urls"] < p["max"]["urls"]
    assert not p["standard"]["deep_checks"] and p["deep"]["deep_checks"]


def test_web_extended_paths_only_at_deep_or_max():
    from allscan.web import EXTENDED_PATHS, SENSITIVE_PATHS, WebModule

    std = WebModule()._paths(_make_ctx())
    assert std == SENSITIVE_PATHS
    ctx = _make_ctx()
    ctx.config.intensity = "deep"
    deep = WebModule()._paths(ctx)
    assert len(deep) > len(std)
    assert {p for p, _, _ in EXTENDED_PATHS} <= {p for p, _, _ in deep}


def _active_findings(intensity):
    import threading
    from allscan.active import ActiveModule
    from tests.demo_vuln_app import make_server

    srv = make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        page = ('<a href="{b}/search?q=hi">s</a><a href="{b}/item?id=1">i</a>'
                '<a href="{b}/redirect?next=/">r</a><a href="{b}/file?name=a.txt">f</a>'
                '<a href="{b}/boom?x=1">b</a>').format(b=base)
        ctx = _make_ctx(target="127.0.0.1", state={
            "web_hosts": [base], "pages": {base: {"body": page, "headers": {}, "cookies": []}}})
        ctx.config.active = True
        ctx.config.timeout = 3
        ctx.config.intensity = intensity
        return {f.evidence.get("type") for f in ActiveModule().run(ctx)}
    finally:
        srv.shutdown()
        srv.server_close()


def test_active_intensity_finds_more_on_demo_app():
    std = _active_findings("standard")
    deep = _active_findings("deep")
    mx = _active_findings("max")
    # standard: the original detection-only checks
    assert {"reflected-input", "open-redirect", "sql-injection", "cors-misconfig"} <= std
    assert not {"template-injection", "crlf-injection", "http-methods", "http-trace",
                "error-disclosure", "path-handling"} & std
    # deep adds the extra non-destructive checks
    assert {"template-injection", "crlf-injection", "http-methods", "http-trace",
            "error-disclosure"} <= deep
    assert "path-handling" not in deep
    # max adds file-handling influence
    assert "path-handling" in mx and deep <= mx


def test_deep_checks_never_send_destructive_methods(monkeypatch):
    """Method probing may only use OPTIONS/TRACE/GET — never PUT/DELETE/POST."""
    import threading
    from allscan.active import ActiveModule
    from tests.demo_vuln_app import make_server

    srv = make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        ctx = _make_ctx(target="127.0.0.1", state={"web_hosts": [base]})
        ctx.config.active, ctx.config.intensity, ctx.config.timeout = True, "max", 3
        seen = []
        orig = ctx.http_request
        monkeypatch.setattr(type(ctx), "http_request",
                            lambda self, m, u, **kw: (seen.append(m.lower()), orig(m, u, **kw))[1])
        ActiveModule().run(ctx)
        assert set(seen) <= {"get", "options", "trace"}
    finally:
        srv.shutdown()
        srv.server_close()
