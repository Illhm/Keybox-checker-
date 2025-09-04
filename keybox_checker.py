
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Keybox Checker (AndroidAttestation XML) - v1.0
Membaca file XML "AndroidAttestation" (format Integrity Box) dan memverifikasi:
- Validitas kunci privat vs sertifikat leaf (cocok/tidak)
- Rantai sertifikat (penandatanganan antar sertifikat)
- Masa berlaku (NotBefore/NotAfter) relatif ke "sekarang"
- Kesesuaian jumlah sertifikat
- Pengenalan Google Hardware Attestation Root (opsional)
Keluaran: ringkasan manusiawi dan/atau JSON.

Dependensi:
  - cryptography
  - python-dateutil (opsional; fallback stdlib tersedia)
"""
import argparse
import base64
import binascii
import dataclasses
import datetime as dt
import json
import sys
import textwrap
import typing as t
import hashlib

try:
    from dateutil.relativedelta import relativedelta  # type: ignore
except Exception:
    relativedelta = None  # fallback pakai perhitungan sederhana

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
except Exception as e:
    print("ERROR: Modul 'cryptography' belum terpasang. "
          "Silakan instal dulu: pip install cryptography python-dateutil", file=sys.stderr)
    sys.exit(2)

try:
    # xml.etree cukup untuk struktur sederhana
    import xml.etree.ElementTree as ET
except Exception as e:
    print("ERROR: Tidak bisa memuat parser XML: %s" % e, file=sys.stderr)
    sys.exit(2)


GOOGLE_HW_ATTESTATION_ROOT_SERIAL_HEX = "f92009e853b6b045"

@dataclasses.dataclass
class CertificateInfo:
    index: int
    cert: x509.Certificate

@dataclasses.dataclass
class KeyChainReport:
    alg: str
    private_key_ok: bool
    cert_count_ok: bool
    chain_ok: bool
    time_ok: bool
    root_trusted_google: bool
    leaf_subject: str
    issuer_common: str
    serial_hex: str
    not_before: dt.datetime
    not_after: dt.datetime
    problems: t.List[str]
    details: t.Dict[str, t.Any]

def pem_chunks_from_xml(node: ET.Element) -> t.Tuple[str, t.List[str], int]:
    """Ekstrak private key PEM dan list certificate PEM dari simpul <Key>."""
    pk_pem = node.findtext("./PrivateKey")
    if pk_pem is None:
        # kadang ada <PrivateKey format="pem"> ... </PrivateKey>
        pk_elem = node.find("./PrivateKey")
        pk_pem = pk_elem.text if pk_elem is not None else None
    if not pk_pem:
        raise ValueError("PrivateKey tidak ditemukan")
    cert_nodes = node.findall("./CertificateChain/Certificate")
    cert_pems = []
    for c in cert_nodes:
        txt = c.text or ""
        cert_pems.append(txt.strip())
    declared = node.findtext("./CertificateChain/NumberOfCertificates")
    declared_num = int(declared) if declared and declared.isdigit() else len(cert_pems)
    return pk_pem.strip(), cert_pems, declared_num

def load_private_key(pem: str):
    return load_pem_private_key(pem.encode("utf-8"), password=None)

def load_certs(pems: t.List[str]) -> t.List[CertificateInfo]:
    certs: t.List[CertificateInfo] = []
    for i, pem in enumerate(pems, start=1):
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
        certs.append(CertificateInfo(index=i, cert=cert))
    return certs

def fmt_name(name: x509.Name) -> str:
    def _get(oid):
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except Exception:
            return None
    parts = []
    title = _get(NameOID.TITLE)
    if title: parts.append(f"title={title}")
    serial = _get(NameOID.SERIAL_NUMBER)
    if serial: parts.append(f"serialNumber={serial}")
    cn = _get(NameOID.COMMON_NAME)
    if cn: parts.append(f"CN={cn}")
    o = _get(NameOID.ORGANIZATION_NAME)
    if o: parts.append(f"O={o}")
    return ", ".join(parts) if parts else name.rfc4514_string()

def check_key_matches_leaf(priv, leaf: x509.Certificate) -> bool:
    pub = leaf.public_key()
    if isinstance(priv, rsa.RSAPrivateKey) and isinstance(pub, rsa.RSAPublicKey):
        return priv.public_key().public_numbers().n == pub.public_numbers().n
    if isinstance(priv, ec.EllipticCurvePrivateKey) and isinstance(pub, ec.EllipticCurvePublicKey):
        pub_nums = pub.public_numbers()
        priv_nums = priv.public_key().public_numbers()
        return (priv_nums.x == pub_nums.x and priv_nums.y == pub_nums.y)
    return False

def verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        pub = issuer.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        else:
            return False
        return True
    except Exception:
        return False

def is_self_signed(cert: x509.Certificate) -> bool:
    return cert.issuer == cert.subject and verify_signature(cert, cert)

def human_timedelta(now: dt.datetime, future: dt.datetime) -> str:
    if future <= now:
        return "kedaluwarsa"
    if relativedelta:
        rd = relativedelta(future, now)
        years = rd.years; months = rd.months; days = rd.days
        parts = []
        if years: parts.append(f"{years} tahun")
        if months: parts.append(f"{months} bulan")
        if days: parts.append(f"{days} hari")
        return " ".join(parts) if parts else "≤1 hari"
    # Fallback kasar (hari)
    delta = future - now
    days = delta.days
    years, rem = divmod(days, 365)
    months, days = divmod(rem, 30)
    parts = []
    if years: parts.append(f"{years} tahun")
    if months: parts.append(f"{months} bulan")
    if days: parts.append(f"{days} hari")
    return " ".join(parts) if parts else "≤1 hari"

def analyze_key_node(key_node: ET.Element, now: dt.datetime) -> KeyChainReport:
    alg = (key_node.attrib.get("algorithm") or "").lower()
    problems: t.List[str] = []
    details: t.Dict[str, t.Any] = {}

    pk_pem, cert_pems, declared = pem_chunks_from_xml(key_node)
    cert_count_ok = declared == len(cert_pems)

    try:
        priv = load_private_key(pk_pem)
    except Exception as e:
        problems.append(f"Gagal memuat PrivateKey: {e}")
        priv = None

    certs = []
    try:
        certs = load_certs(cert_pems)
    except Exception as e:
        problems.append(f"Gagal memuat sertifikat: {e}")

    if not certs:
        # Tidak ada sertifikat, keluar cepat
        return KeyChainReport(alg=alg, private_key_ok=False, cert_count_ok=cert_count_ok,
                              chain_ok=False, time_ok=False, root_trusted_google=False,
                              leaf_subject="-", issuer_common="-", serial_hex="-",
                              not_before=now, not_after=now, problems=problems, details=details)

    leaf = certs[0].cert
    issuer_common = fmt_name(leaf.issuer)
    leaf_subject = fmt_name(leaf.subject)
    serial_hex = format(leaf.serial_number, 'x')

    # key vs leaf
    private_key_ok = False
    if priv is not None:
        private_key_ok = check_key_matches_leaf(priv, leaf)
        if not private_key_ok:
            problems.append("PrivateKey tidak cocok dengan sertifikat leaf")

    # chain verify
    chain_ok = True
    for i in range(0, len(certs)-1):
        if not verify_signature(certs[i].cert, certs[i+1].cert):
            chain_ok = False
            problems.append(f"Tanda tangan sertifikat #{i+1} tidak dapat diverifikasi oleh issuer #{i+2}")
    # root self-signed check
    if not is_self_signed(certs[-1].cert):
        chain_ok = False
        problems.append("Sertifikat root bukan self-signed/verify gagal")

    # time check (gunakan batas paling ketat: leaf)
    not_before = leaf.not_valid_before.replace(tzinfo=None)
    not_after = leaf.not_valid_after.replace(tzinfo=None)
    time_ok = (not_before <= now <= not_after)
    if not time_ok:
        problems.append("Sertifikat leaf di luar masa berlaku")

    # Google root detection (opsional)
    root = certs[-1].cert
    try:
        root_subj_serial = root.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
    except Exception:
        root_subj_serial = ""
    root_trusted_google = (str(root_subj_serial).lower() == GOOGLE_HW_ATTESTATION_ROOT_SERIAL_HEX)

    # Emit beberapa detail tambahan
    details["certs"] = [{
        "index": ci.index,
        "subject": fmt_name(ci.cert.subject),
        "issuer": fmt_name(ci.cert.issuer),
        "serial_hex": format(ci.cert.serial_number, 'x'),
        "sig_algo": ci.cert.signature_hash_algorithm.name if ci.cert.signature_hash_algorithm else "unknown",
        "not_before": ci.cert.not_valid_before.isoformat(),
        "not_after": ci.cert.not_valid_after.isoformat(),
        "fingerprint_sha256": ci.cert.fingerprint(hashes.SHA256()).hex(),
    } for ci in certs]

    return KeyChainReport(
        alg=alg,
        private_key_ok=private_key_ok,
        cert_count_ok=cert_count_ok,
        chain_ok=chain_ok,
        time_ok=time_ok,
        root_trusted_google=root_trusted_google,
        leaf_subject=leaf_subject,
        issuer_common=issuer_common,
        serial_hex=serial_hex,
        not_before=not_before,
        not_after=not_after,
        problems=problems,
        details=details
    )

def print_human(report: KeyChainReport, idx: int, now: dt.datetime, width: int = 80):
    check = lambda b: "✅" if b else "❌"
    print(f"🔑 Key Chain: #{idx} ({report.alg.upper() if report.alg else 'unknown'})")
    print(f"   • Kunci cocok dgn leaf       : {check(report.private_key_ok)}")
    print(f"   • Jumlah sertifikat sesuai   : {check(report.cert_count_ok)}")
    print(f"   • Rantai (signature) valid   : {check(report.chain_ok)}")
    print(f"   • Masa berlaku OK (leaf)     : {check(report.time_ok)}")
    print(f"   • Root Google HW Attestation : {check(report.root_trusted_google)}")
    print(f"   • Leaf Subject               : {report.leaf_subject}")
    print(f"   • Leaf Issuer                : {report.issuer_common}")
    print(f"   • Leaf Serial (hex)          : {report.serial_hex}")
    dur = human_timedelta(now, report.not_after)
    print(f"   • Berlaku hingga             : {report.not_after.date()}  (≈ {dur})")
    if report.problems:
        print("   • Catatan/masalah:")
        for p in report.problems:
            print("     - " + p)

def main():
    ap = argparse.ArgumentParser(description="Checker Keybox (AndroidAttestation XML)")
    ap.add_argument("xml_path", help="Path ke file XML keybox")
    ap.add_argument("--json", action="store_true", help="Keluarkan JSON ringkas")
    ap.add_argument("--ignore", choices=["rsa", "ecdsa"], help="Abaikan jenis kunci tertentu")
    ap.add_argument("--full-json", action="store_true", help="JSON lengkap termasuk detail sertifikat")
    args = ap.parse_args()

    try:
        tree = ET.parse(args.xml_path)
    except Exception as e:
        print(f"ERROR: Gagal membaca XML: {e}", file=sys.stderr)
        sys.exit(2)

    root = tree.getroot()
    now = dt.datetime.utcnow()

    key_nodes = root.findall(".//Keybox/Key")
    if not key_nodes:
        # fallback untuk struktur tanpa Keybox wrapper
        key_nodes = root.findall(".//Key")

    reports: t.List[KeyChainReport] = []
    for kn in key_nodes:
        alg = (kn.attrib.get("algorithm") or "").lower()
        if args.ignore and alg == args.ignore:
            continue
        reports.append(analyze_key_node(kn, now))

    if args.json or args.full_json:
        out = []
        for i, r in enumerate(reports, start=1):
            base = {
                "index": i,
                "algorithm": r.alg,
                "private_key_ok": r.private_key_ok,
                "cert_count_ok": r.cert_count_ok,
                "chain_ok": r.chain_ok,
                "time_ok": r.time_ok,
                "root_google_hw_attestation": r.root_trusted_google,
                "leaf_subject": r.leaf_subject,
                "leaf_issuer": r.issuer_common,
                "leaf_serial_hex": r.serial_hex,
                "not_before": r.not_before.isoformat(),
                "not_after": r.not_after.isoformat(),
                "valid_for": human_timedelta(now, r.not_after),
                "problems": r.problems,
            }
            if args.full_json:
                base["details"] = r.details
            out.append(base)
        print(json.dumps({"generated_at_utc": now.isoformat(), "chains": out}, indent=2, ensure_ascii=False))
        return

    print("🔎 HASIL PEMERIKSAAN KEYBOX")
    print("---------------------------")
    if not reports:
        print("Tidak ada key chain yang diperiksa (mungkin terfilter '--ignore').")
        sys.exit(1)
    for i, r in enumerate(reports, start=1):
        print_human(r, i, now)
        print()
    # ringkas: deteksi integritas kuat (EC + root Google + valid semua)
    strong = any(r.alg == "ecdsa" and r.private_key_ok and r.chain_ok and r.time_ok and r.root_trusted_google for r in reports)
    if strong:
        # cari masa berlaku terpendek dari chain yang memenuhi syarat
        valid_untils = [r.not_after for r in reports if (r.alg == "ecdsa" and r.private_key_ok and r.chain_ok and r.time_ok and r.root_trusted_google)]
        if valid_untils:
            shortest = min(valid_untils)
            print(f"💚 Status: VALID untuk STRONG integrity. Berlaku s/d {shortest.date()} (≈ {human_timedelta(now, shortest)}).")
    else:
        print("⚠️ Status: Tidak memenuhi kriteria 'STRONG' (cek catatan di atas).")

if __name__ == "__main__":
    main()
