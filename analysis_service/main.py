import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proto"))

import re
import concurrent.futures
import grpc
from shared.logger import configure_logging
from shared.config import get_settings
import analysis_pb2
import analysis_pb2_grpc

log = configure_logging("analysis_service")
cfg = get_settings()

URGENT_WORDS = re.compile(
    r"\b(urgent|immediate|verify|suspend|click here|act now|limited time|"
    r"confirm your|update your|account|password|banking|login|credential|"
    r"security alert|unusual activity|blocked|compromised)\b",
    re.I,
)
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".loan", ".work", ".gq", ".cf", ".tk",
                   ".ml", ".ga", ".men", ".win", ".racing", ".stream"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"}
IP_URL = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}")
HOMOGLYPH = re.compile(r"(paypa1|g00gle|arnazon|micros0ft|app1e|faceb00k)", re.I)
URL_DOMAIN = re.compile(r"https?://([^/?\s]+)")


def url_domains(urls):
    out = []
    for u in urls:
        m = URL_DOMAIN.match(u)
        if m:
            out.append(m.group(1).lower())
    return out


def sender_domain(sender):
    m = re.search(r"@([\w.\-]+)", sender)
    return m.group(1).lower() if m else ""


def add_rule(flags, reasons, name, hit, pts, msg):
    flags[name] = bool(hit)
    if hit:
        reasons.append(msg)
        return pts
    return 0


def score_email(declared_sender, subject, body, urls, has_attachments):
    points = 0
    reasons = []
    flags = {}
    text = f"{subject} {body}"
    domains = url_domains(urls)
    snd = sender_domain(declared_sender)

    hits = URGENT_WORDS.findall(text)
    n = len({w.lower() for w in hits})
    points += add_rule(flags, reasons, "urgent_language", n > 0, min(n * 8, 25),
                       f"Manipulative language detected ({n} trigger words)")

    bad = next((d for d in domains if any(d.endswith(t) for t in SUSPICIOUS_TLDS)), None)
    points += add_rule(flags, reasons, "suspicious_tld", bad, 20, f"URL uses suspicious TLD: {bad}")

    points += add_rule(flags, reasons, "ip_url", any(IP_URL.match(u) for u in urls), 25,
                       "Direct IP address used in URL (no hostname)")

    short = next((d for d in domains if d in SHORTENERS), None)
    points += add_rule(flags, reasons, "url_shortener", short, 15, f"URL shortener detected ({short})")

    points += add_rule(flags, reasons, "homoglyph", bool(HOMOGLYPH.search(text)), 30,
                       "Typosquatting or homoglyph brand impersonation detected")

    mismatch = snd and domains and any(snd not in d and d not in SHORTENERS for d in domains)
    points += add_rule(flags, reasons, "domain_mismatch", mismatch, 15,
                       f"Declared sender domain ({snd}) differs from link domain(s)")

    points += add_rule(flags, reasons, "has_attachments", has_attachments, 10,
                       "Email announces attachments — common malware delivery vector")
    points += add_rule(flags, reasons, "many_urls", len(urls) > 5, 5,
                       f"Unusually high number of URLs ({len(urls)})")
    points += add_rule(flags, reasons, "empty_body", len(body.strip()) < 30, 10,
                       "Near-empty body — possible image-only phishing")

    score = min(points, 100)
    risk = "high" if score >= 60 else "medium" if score >= 30 else "low"
    if not reasons:
        reasons.append("No suspicious indicators detected")
    return score, risk, reasons, flags


class AnalyzerServicer(analysis_pb2_grpc.AnalyzerServicer):
    def Analyze(self, request, context):
        try:
            score, risk, reasons, flags = score_email(
                request.declared_sender, request.subject, request.body,
                list(request.urls), request.has_attachments,
            )
        except Exception as e:
            log.error("analysis.scoring_error", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Analysis failed")
            return analysis_pb2.AnalyzeResponse()

        log.info("analysis.result", score=score, risk=risk)
        return analysis_pb2.AnalyzeResponse(
            risk_level=risk, score=score, reasons=reasons, flags=flags,
        )


def serve():
    server = grpc.server(
        concurrent.futures.ThreadPoolExecutor(max_workers=4),
        options=[("grpc.max_receive_message_length", 1024 * 1024)],
    )
    analysis_pb2_grpc.add_AnalyzerServicer_to_server(AnalyzerServicer(), server)
    addr = f"[::]:{cfg.analysis_grpc_port}"
    server.add_insecure_port(addr)
    log.info("analysis_service.started", addr=addr)
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()

