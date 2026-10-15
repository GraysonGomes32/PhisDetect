#!/usr/bin/env python3
"""phishdetect - rule-based feature extraction + logistic regression phishing flagger.

Pure standard library (no pip installs).

  python phishdetect.py eval                     # 5-fold CV on synthetic data, FP report
  python phishdetect.py eval --data corpus/      # corpus/phish/*.eml and corpus/ham/*.eml
  python phishdetect.py train [--data DIR]       # saves model.json
  python phishdetect.py samples DIR              # writes two example .eml files
  python phishdetect.py scan a.eml b.eml         # verdict + explanation per email
"""
import argparse, json, math, random, re, sys
from email import policy
from email.message import EmailMessage
from email.parser import Parser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

# ----------------------------------------------------------------- helpers
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
BAD_TLDS = {"top", "xyz", "info", "click", "work", "zip", "country", "gq", "tk", "ml", "cf", "ga", "support"}
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me", "mail.com"}
BRANDS = ["paypal", "amazon", "microsoft", "apple", "google", "netflix", "chase", "dhl", "docusign", "dropbox"]

URGENT = ["urgent", "immediately", "within 24 hours", "act now", "expires", "final notice",
          "last warning", "verify now", "as soon as possible", "right away"]
CRED = ["password", "verify your account", "confirm your identity", "log in", "login", "sign in",
        "social security", "credit card", "bank account", "update your payment", "security code"]
THREAT = ["suspended", "locked", "terminated", "unauthorized", "unusual activity", "closed",
          "legal action", "penalty", "limited"]
GENERIC = ["dear customer", "dear user", "dear account holder", "dear member", "valued customer"]

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)


def reg_domain(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "gov", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


class Anchors(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.text, self._href = [], [], None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href", "")
            self._buf = []

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None


def parse_email(raw):
    return Parser(policy=policy.default).parsestr(raw)


def bodies(msg):
    plain = html = ""
    for p in msg.walk():
        try:
            if p.get_content_type() == "text/plain":
                plain += p.get_content()
            elif p.get_content_type() == "text/html":
                html += p.get_content()
        except Exception:
            pass
    return plain, html


# ------------------------------------------------------- feature extraction
FEATURES = [
    "replyto_mismatch", "replyto_freemail", "display_brand_mismatch", "auth_fail",
    "n_urls", "url_ip_host", "url_shortener", "url_at_symbol", "url_punycode",
    "url_deep_subdomains", "url_http_only", "url_bad_tld", "url_hyphens",
    "href_text_mismatch", "urgent_terms", "cred_terms", "threat_terms", "generic_greeting",
    "exclaims", "caps_subject",
]


def extract(msg):
    """Return (feature dict, {feature: human-readable reason})."""
    f = {k: 0.0 for k in FEATURES}
    why = {}

    def flag(name, value, reason):
        f[name] = value
        if value:
            why[name] = reason

    name, addr = parseaddr(str(msg.get("From", "")))
    sdom = reg_domain(addr.split("@")[-1]) if "@" in addr else ""
    _, rt = parseaddr(str(msg.get("Reply-To", "")))
    rdom = reg_domain(rt.split("@")[-1]) if "@" in rt else ""
    if rdom and sdom and rdom != sdom:
        flag("replyto_mismatch", 1, f"Reply-To domain ({rdom}) differs from sender domain ({sdom})")
        flag("replyto_freemail", float(rdom in FREEMAIL), f"Replies are routed to a free mail provider ({rdom})")
    for b in BRANDS:
        if b in name.lower() and b not in sdom:
            flag("display_brand_mismatch", 1, f"Display name '{name}' claims '{b}' but mail comes from {sdom}")
            break
    auth = str(msg.get("Authentication-Results", "")).lower()
    if re.search(r"(spf|dkim|dmarc)=(fail|softfail|none)", auth):
        flag("auth_fail", 1, "SPF/DKIM/DMARC check failed or missing")

    plain, html = bodies(msg)
    anchors = Anchors()
    if html:
        anchors.feed(html)
    body = plain or " ".join(anchors.text)
    subject = str(msg.get("Subject", ""))
    text = (subject + " " + body).lower()

    hrefs = [h for h, _ in anchors.links if h.startswith("http")]
    urls = list(dict.fromkeys(hrefs + URL_RE.findall(plain)))
    f["n_urls"] = float(min(len(urls), 8))
    for u in urls:
        h = host_of(u)
        if not h:
            continue
        tld = h.rsplit(".", 1)[-1]
        if IP_RE.match(h):
            flag("url_ip_host", 1, f"Link points to a raw IP address ({h})")
        if reg_domain(h) in SHORTENERS:
            flag("url_shortener", 1, f"Link uses a URL shortener ({h})")
        if "@" in urlparse(u).netloc:
            flag("url_at_symbol", 1, f"Link contains '@' to disguise the real host ({u[:50]})")
        if "xn--" in h:
            flag("url_punycode", 1, f"Link uses punycode / lookalike characters ({h})")
        if h.count(".") >= 4:
            flag("url_deep_subdomains", 1, f"Link has an unusually deep subdomain chain ({h})")
        if u.lower().startswith("http://"):
            flag("url_http_only", 1, f"Link is not HTTPS ({h})")
        if tld in BAD_TLDS:
            flag("url_bad_tld", 1, f"Link uses a TLD common in abuse (.{tld}: {h})")
        if reg_domain(h).split(".")[0].count("-") >= 2:
            flag("url_hyphens", 1, f"Link domain is hyphen-stuffed ({reg_domain(h)})")
    for href, label in anchors.links:
        m = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", label.lower())
        if m and href.startswith("http") and reg_domain(m.group(0)) != reg_domain(host_of(href)):
            flag("href_text_mismatch", 1, f"Link text shows '{m.group(0)}' but goes to {host_of(href)}")
            break

    def hits(lex):
        return [t for t in lex if t in text]
    for key, lex, label in [("urgent_terms", URGENT, "Urgency language"),
                            ("cred_terms", CRED, "Credential/financial requests"),
                            ("threat_terms", THREAT, "Account-threat language")]:
        h = hits(lex)
        flag(key, float(min(len(h), 4)), f"{label}: {', '.join(h[:4])}")
    flag("generic_greeting", float(bool(hits(GENERIC))), "Generic greeting instead of your name")
    flag("exclaims", float(min(text.count("!"), 4)), "Multiple exclamation marks")
    letters = [c for c in subject if c.isalpha()]
    flag("caps_subject", float(len(letters) > 6 and sum(c.isupper() for c in letters) / len(letters) > 0.6),
         "Subject line is mostly capitals")
    return f, why


def vectorize(f):
    return [f[k] for k in FEATURES]


# ------------------------------------------------------------- classifier
class LogReg:
    def fit(self, X, y, epochs=300, lr=0.2, l2=0.01):
        n, d = len(X), len(X[0])
        self.mu = [sum(r[j] for r in X) / n for j in range(d)]
        self.sd = [(sum((r[j] - self.mu[j]) ** 2 for r in X) / n) ** 0.5 or 1.0 for j in range(d)]
        Z = [self.z(r) for r in X]
        self.w, self.b = [0.0] * d, 0.0
        for _ in range(epochs):
            gw, gb = [0.0] * d, 0.0
            for zi, yi in zip(Z, y):
                e = self.sig(sum(w * v for w, v in zip(self.w, zi)) + self.b) - yi
                gb += e
                for j in range(d):
                    gw[j] += e * zi[j]
            self.w = [w - lr * (g / n + l2 * w) for w, g in zip(self.w, gw)]
            self.b -= lr * gb / n
        return self

    def z(self, x):
        return [(v - m) / s for v, m, s in zip(x, self.mu, self.sd)]

    @staticmethod
    def sig(t):
        return 1 / (1 + math.exp(-max(-30, min(30, t))))

    def proba(self, x):
        return self.sig(sum(w * v for w, v in zip(self.w, self.z(x))) + self.b)

    def contributions(self, x):
        return sorted(((w * v, n) for w, v, n in zip(self.w, self.z(x), FEATURES)), reverse=True)

    def dump(self, path):
        Path(path).write_text(json.dumps(self.__dict__))

    @classmethod
    def load(cls, path):
        m = cls()
        m.__dict__.update(json.loads(Path(path).read_text()))
        return m


# ------------------------------------------------------------ data sources
def load_dir(root):
    X, y, names = [], [], []
    for label, sub in [(1, "phish"), (0, "ham")]:
        for p in sorted(Path(root, sub).glob("*.eml")):
            f, _ = extract(parse_email(p.read_text(errors="ignore")))
            X.append(vectorize(f)); y.append(label); names.append(str(p))
    return X, y, names


def synth_email(rng, phish):
    """Synthetic sample with deliberately hard cases on both sides.
    NOTE: metrics on this data only prove the plumbing works - use a real corpus."""
    brand = rng.choice(BRANDS)
    real = f"{brand}.com"
    m = EmailMessage()
    p = rng.random
    if phish:
        r = p()
        sender = (f"secure-{brand}-login.top" if r < .4 else "gmail.com" if r < .65
                  else f"{brand}-support.xyz" if r < .8 else real)  # 20% spoof/compromise of real domain
        m["From"] = f'"{brand.title()} Support" <noreply@{sender}>'
        if p() < .5:
            m["Reply-To"] = f"help.desk{rng.randint(1,99)}@{rng.choice(['gmail.com','outlook.com','mail.com'])}"
        if p() < .6:
            m["Authentication-Results"] = "mx.example; spf=fail; dkim=none; dmarc=fail"
        bad = rng.choice([f"{brand}-verify-account.top", f"login.{brand}.secure.update.example.info",
                          "bit.ly", f"203.0.113.{rng.randint(1,254)}", f"{brand}.com.account-check.xyz"])
        scheme = "http" if p() < .4 else "https"
        url = f"{scheme}://{bad}/signin?id={rng.randint(1000,9999)}"
        shown = real if p() < .5 else url
        m["Subject"] = rng.choice(["Action required: verify your account", "URGENT: account suspended",
                                    "Unusual activity detected", "Payment failed - update now", "Your package is on hold"])
        bits = [rng.choice(["Dear customer,", "Hello,", "Dear user,"])]
        for pool, prob in [(["Your account has been suspended due to unusual activity."], .7),
                           (["Please verify your account password immediately.", "Confirm your identity within 24 hours."], .7),
                           (["Failure to act will result in legal action!"], .3)]:
            if p() < prob:
                bits.append(rng.choice(pool))
    else:
        r = p()
        kind = "newsletter" if r < .35 else "receipt" if r < .6 else "colleague" if r < .85 else "list"
        dom = real if kind in ("newsletter", "receipt") else rng.choice(["gmail.com", "contoso.org", "university.edu"])
        m["From"] = (f'"{brand.title()}" <no-reply@{dom}>' if dom == real else f"Sam Lee <sam@{dom}>")
        if kind == "list" or (kind == "newsletter" and p() < .3):
            m["Reply-To"] = f"list-admin@{rng.choice(['mailchimp.com','groups.io'])}"
        if p() < .8:
            m["Authentication-Results"] = "mx.example; spf=pass; dkim=pass; dmarc=pass"
        host = f"{rng.choice(['click','links','track'])}.{rng.choice(['mailchimp.com','sendgrid.net'])}" \
            if kind == "newsletter" and p() < .6 else f"www.{real}"
        if p() < .06:
            host = "bit.ly"
        url = f"https://{host}/path/{rng.randint(1000,9999)}"
        shown = real if kind == "newsletter" and p() < .5 else url
        m["Subject"] = rng.choice(["Your receipt", "Weekly digest", "Lunch tomorrow?", "Meeting notes",
                                    "Invoice due soon", "Reset your password", "Security alert: new sign-in"])
        bits = [rng.choice(["Hi Alex,", "Hello Alex,", "Hi team,"]),
                rng.choice(["Thanks for your order.", "Here are this week's updates!", "Notes attached below."])]
        if p() < .15:
            bits.append(rng.choice(["Your invoice is due within 24 hours.", "Please log in to review your statement.",
                                    "If you requested a password reset, use the link below."]))
    m["To"] = "alex@example.org"
    bits.append(f"Visit: {url}")
    m.set_content("\n".join(bits))
    m.add_alternative("<html><body>" + "<br>".join(bits[:-1]) +
                      f'<br><a href="{url}">{shown}</a></body></html>', subtype="html")
    return m.as_string()


def synth_data(n, seed=7):
    rng = random.Random(seed)
    X, y = [], []
    for i in range(n):
        ph = rng.random() < 0.35
        f, _ = extract(parse_email(synth_email(rng, ph)))
        X.append(vectorize(f)); y.append(int(ph))
    return X, y, None


# ------------------------------------------------------------- evaluation
def cross_val(X, y, k=5, seed=1):
    rng = random.Random(seed)
    idx = {c: [i for i, v in enumerate(y) if v == c] for c in (0, 1)}
    folds = [[] for _ in range(k)]
    for c in idx:
        rng.shuffle(idx[c])
        for j, i in enumerate(idx[c]):
            folds[j % k].append(i)
    scores = [0.0] * len(y)
    for te in folds:
        tr = [i for i in range(len(y)) if i not in set(te)]
        m = LogReg().fit([X[i] for i in tr], [y[i] for i in tr])
        for i in te:
            scores[i] = m.proba(X[i])
    return scores


def metrics(scores, y, t):
    tp = sum(s >= t and v for s, v in zip(scores, y)); fp = sum(s >= t and not v for s, v in zip(scores, y))
    fn = sum(s < t and v for s, v in zip(scores, y)); tn = sum(s < t and not v for s, v in zip(scores, y))
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=tp / (tp + fp or 1),
                recall=tp / (tp + fn or 1), fpr=fp / (fp + tn or 1))


def report(scores, y):
    print(f"\n{len(y)} emails ({sum(y)} phish / {len(y)-sum(y)} legit), out-of-fold predictions\n")
    print(f"{'thresh':>6} {'FPR':>7} {'FP':>4} {'precision':>9} {'recall':>7} {'FN':>4}")
    for t in (0.3, 0.5, 0.7, 0.9):
        r = metrics(scores, y, t)
        print(f"{t:>6} {r['fpr']:>7.1%} {r['fp']:>4} {r['precision']:>9.1%} {r['recall']:>7.1%} {r['fn']:>4}")
    ok = [t / 100 for t in range(1, 100) if metrics(scores, y, t / 100)["fpr"] <= 0.01]
    if ok:
        t = ok[0]; r = metrics(scores, y, t)
        print(f"\nLowest threshold with FPR <= 1%: {t:.2f}  (recall {r['recall']:.1%})")
    else:
        print("\nNo threshold achieves FPR <= 1%.")


# -------------------------------------------------------------------- CLI
def explain(path, model, threshold):
    f, why = extract(parse_email(Path(path).read_text(errors="ignore")))
    x = vectorize(f)
    p = model.proba(x)
    print(f"\n=== {path}\nPhishing probability: {p:.1%}  ->  {'FLAGGED' if p >= threshold else 'looks OK'} (threshold {threshold})")
    contribs = [(c, n) for c, n in model.contributions(x) if c > 0.05 and n in why]
    if contribs:
        print("Why (ranked by model contribution):")
        for c, n in contribs:
            print(f"  +{c:.2f}  {why[n]}")
    else:
        print("No suspicious signals found.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["eval", "train", "scan", "samples"])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--data"); ap.add_argument("--n", type=int, default=800)
    ap.add_argument("--threshold", type=float, default=0.5)
    a = ap.parse_args()
    get = (lambda: load_dir(a.data)) if a.data else (lambda: synth_data(a.n))
    if a.cmd == "eval":
        X, y, _ = get(); report(cross_val(X, y), y)
    elif a.cmd == "train":
        X, y, _ = get(); m = LogReg().fit(X, y); m.dump("model.json")
        print("Saved model.json. Strongest weights:")
        for w, n in sorted(zip(m.w, FEATURES), reverse=True)[:6]:
            print(f"  {w:+.2f} {n}")
    elif a.cmd == "samples":
        d = Path(a.paths[0] if a.paths else "."); d.mkdir(exist_ok=True)
        rng = random.Random(3)
        (d / "phish_sample.eml").write_text(synth_email(rng, True))
        (d / "legit_sample.eml").write_text(synth_email(rng, False))
        print("Wrote", d / "phish_sample.eml", "and", d / "legit_sample.eml")
    else:
        if Path("model.json").exists():
            m = LogReg.load("model.json")
        else:
            print("(no model.json - training on synthetic data)")
            X, y, _ = get(); m = LogReg().fit(X, y)
        for pth in a.paths:
            explain(pth, m, a.threshold)


if __name__ == "__main__":
    main()
