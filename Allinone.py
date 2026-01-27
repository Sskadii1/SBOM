#!/usr/bin/env python3

import argparse
import csv
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


def doc_json(duong_dan: str) -> Any:
    with open(duong_dan, "r", encoding="utf-8") as f:
        return json.load(f)


def ghi_json(duong_dan: str, du_lieu: Any) -> None:
    with open(duong_dan, "w", encoding="utf-8") as f:
        json.dump(du_lieu, f, ensure_ascii=False, indent=2)


def tao_thu_muc(duong_dan: str) -> None:
    os.makedirs(duong_dan, exist_ok=True)


def lay_purl_tu_goi(pkg: Dict[str, Any]) -> str:
    for r in (pkg.get("externalRefs") or []):
        if r.get("referenceType") == "purl":
            return r.get("referenceLocator") or ""
    return ""


def lay_spdx_doc_bat_ky_cau_truc(root: Any) -> Dict[str, Any]:
    if isinstance(root, dict) and "sbom" in root and isinstance(root["sbom"], dict):
        return root["sbom"]

    docs: List[Dict[str, Any]] = []

    def tim_spdx_docs(obj: Any, do_sau: int = 0, do_sau_toi_da: int = 6) -> None:
        if do_sau > do_sau_toi_da:
            return
        if isinstance(obj, dict):
            if "spdxVersion" in obj and ("packages" in obj or "relationships" in obj):
                docs.append(obj)
                return
            for v in obj.values():
                tim_spdx_docs(v, do_sau + 1, do_sau_toi_da)
        elif isinstance(obj, list):
            for it in obj[:5000]:
                tim_spdx_docs(it, do_sau + 1, do_sau_toi_da)

    tim_spdx_docs(root)

    if not docs:
        raise ValueError("Không tìm thấy tài liệu SPDX trong cấu trúc JSON.")
    return docs[0]


def buoc_xem_tom_tat(sbom_json: str) -> None:
    root = doc_json(sbom_json)
    doc = lay_spdx_doc_bat_ky_cau_truc(root)
    pkgs = doc.get("packages", []) or []
    rels = doc.get("relationships", []) or []

    mau = []
    for p in pkgs[:3]:
        mau.append({
            "ten": p.get("name"),
            "phien_ban": p.get("versionInfo"),
            "purl": lay_purl_tu_goi(p) or None,
            "SPDXID": p.get("SPDXID"),
        })

    print("Tệp:", sbom_json)
    print("spdxVersion:", doc.get("spdxVersion"))
    print("Tên SBOM:", doc.get("name"))
    print("Số package:", len(pkgs))
    print("Số relationship:", len(rels))
    print("Ví dụ 3 package:", mau)


def buoc_xuat_csv(sbom_json: str, csv_dau_ra: str) -> None:
    root = doc_json(sbom_json)
    doc = lay_spdx_doc_bat_ky_cau_truc(root)
    pkgs = doc.get("packages", []) or []

    dong = []
    for p in pkgs:
        dong.append({
            "spdxid": p.get("SPDXID", ""),
            "ten": p.get("name", ""),
            "phien_ban": p.get("versionInfo", ""),
            "purl": lay_purl_tu_goi(p),
        })

    with open(csv_dau_ra, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["spdxid", "ten", "phien_ban", "purl"])
        w.writeheader()
        w.writerows(dong)

    print("Đã ghi:", csv_dau_ra, "| Số dòng:", len(dong))


BANG_HE_SINH_THAI = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "crates": "crates.io",
    "composer": "Packagist",
}


def tach_purl_co_ban(purl: str) -> Optional[Tuple[str, str, Optional[str]]]:
    m = re.match(r"^pkg:([^/]+)/([^@]+)(?:@(.+))?$", purl or "")
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


def buoc_lam_giau_osv(csv_du_vao: str, json_dau_ra: str, che_do: str = "thong_minh") -> None:
    try:
        import requests
    except ImportError:
        print("Thiếu thư viện: requests. Cài bằng: pip install requests")
        sys.exit(2)

    ds = []
    with open(csv_du_vao, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            if row.get("purl"):
                ds.append(row)

    queries = []
    meta = []
    for it in ds:
        purl = it["purl"]

        if che_do == "purl":
            queries.append({"package": {"purl": purl}})
            meta.append(it)
            continue

        parsed = tach_purl_co_ban(purl)
        if not parsed:
            queries.append({"package": {"purl": purl}})
            meta.append(it)
            continue

        loai, ten, phien_ban = parsed
        he_sinh_thai = BANG_HE_SINH_THAI.get(loai)

        if he_sinh_thai and phien_ban:
            queries.append({"package": {"ecosystem": he_sinh_thai, "name": ten}, "version": phien_ban})
            meta.append(it)
        else:
            queries.append({"package": {"purl": purl}})
            meta.append(it)

    payload = {"queries": queries}
    resp = requests.post("https://api.osv.dev/v1/querybatch", json=payload, timeout=60)
    resp.raise_for_status()
    data = resp.json()

    ket_qua = []
    for it, res in zip(meta, data.get("results", [])):
        vulns = res.get("vulns") or []
        ket_qua.append({
            "purl": it["purl"],
            "ten": it.get("ten", it.get("name", "")),
            "phien_ban": it.get("phien_ban", it.get("version", "")),
            "so_lo_hong": len(vulns),
            "danh_sach_id": [v.get("id") for v in vulns if v.get("id")],
        })

    ghi_json(json_dau_ra, ket_qua)
    print("Đã ghi:", json_dau_ra, "| Số package có purl:", len(ket_qua))


def buoc_tao_bao_cao_md(findings_json: str, md_dau_ra: str) -> None:
    items = doc_json(findings_json)
    dong = []
    dong.append("# Tóm tắt lỗ hổng từ SBOM\n")

    for it in items:
        dong.append(f"## {it.get('ten','')} ({it.get('purl','')})")
        dong.append(f"- Phiên bản: `{it.get('phien_ban','')}`")
        dong.append(f"- Số lỗ hổng tìm thấy: **{it.get('so_lo_hong',0)}**")

        ids = it.get("danh_sach_id") or []
        if ids:
            dong.append("- Danh sách ID:")
            for vid in ids[:20]:
                dong.append(f"  - {vid}")
        dong.append("")

    with open(md_dau_ra, "w", encoding="utf-8") as f:
        f.write("\n".join(dong))

    print("Đã ghi:", md_dau_ra)


def he_sinh_thai_tu_purl(purl: str) -> str:
    m = re.match(r"^pkg:([^/]+)/", purl or "")
    return m.group(1) if m else ""


def buoc_tao_corpus(sbom_json: str, findings_json: str, jsonl_dau_ra: str) -> None:
    root = doc_json(sbom_json)
    sbom = lay_spdx_doc_bat_ky_cau_truc(root)
    findings = doc_json(findings_json)

    ten_repo = sbom.get("name") or sbom.get("documentName") or "khong_ro"
    packages = sbom.get("packages", []) or []

    find_by_purl = {x["purl"]: x for x in findings if x.get("purl")}

    chunks = []
    tong_lo_hong = sum(x.get("so_lo_hong", x.get("vuln_count", 0)) for x in findings)

    text_repo = (
        f"SBOM/Repo: {ten_repo}\n"
        f"Tổng số package: {len(packages)}\n"
        f"Tổng số lỗ hổng (OSV): {tong_lo_hong}\n"
        f"Tệp SBOM: {sbom_json}\n"
    )

    chunks.append({
        "id": f"{ten_repo}::tom_tat_repo",
        "type": "repo",
        "repo": ten_repo,
        "purl": "",
        "ecosystem": "",
        "text": text_repo,
        "meta": {"sbom_file": sbom_json},
    })

    for p in packages:
        ten = p.get("name", "")
        phien_ban = p.get("versionInfo", "")
        spdxid = p.get("SPDXID", "")
        purl = lay_purl_tu_goi(p)
        eco = he_sinh_thai_tu_purl(purl)

        fnd = find_by_purl.get(purl) if purl else None
        so_lo_hong = fnd.get("so_lo_hong", fnd.get("vuln_count", 0)) if fnd else 0
        ds_id = fnd.get("danh_sach_id", fnd.get("vuln_ids", [])) if fnd else []

        text_pkg = (
            f"Package: {ten}\n"
            f"Phiên bản: {phien_ban}\n"
            f"PURL: {purl}\n"
            f"SPDXID: {spdxid}\n"
            f"Số lỗ hổng (OSV): {so_lo_hong}\n"
        )
        if ds_id:
            text_pkg += "ID lỗ hổng:\n" + "\n".join([f"- {vid}" for vid in ds_id[:30]]) + "\n"

        chunks.append({
            "id": f"{ten_repo}::pkg::{purl or spdxid}",
            "type": "package",
            "repo": ten_repo,
            "purl": purl,
            "ecosystem": eco,
            "text": text_pkg,
            "meta": {"spdxid": spdxid, "ten": ten, "phien_ban": phien_ban, "sbom_file": sbom_json},
        })

    for x in findings:
        purl = x.get("purl", "")
        ds_id = x.get("danh_sach_id", x.get("vuln_ids", [])) or []
        for vid in ds_id[:50]:
            chunks.append({
                "id": f"{ten_repo}::lo_hong::{vid}::{purl}",
                "type": "vuln",
                "repo": ten_repo,
                "purl": purl,
                "ecosystem": he_sinh_thai_tu_purl(purl),
                "text": f"ID lỗ hổng: {vid}\nGói bị ảnh hưởng: {purl}\n",
                "meta": {"vuln_id": vid, "sbom_file": sbom_json},
            })

    with open(jsonl_dau_ra, "w", encoding="utf-8") as f:
        for c in chunks:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    print("Đã ghi:", jsonl_dau_ra, "| Số chunk:", len(chunks))


def buoc_index_chroma(corpus_jsonl: str, thu_muc_luu: str, dung_embedding: bool = True) -> None:
    try:
        import chromadb
    except ImportError:
        print("Thiếu thư viện: chromadb. Cài bằng: pip install chromadb")
        sys.exit(2)

    tao_thu_muc(thu_muc_luu)
    client = chromadb.PersistentClient(path=thu_muc_luu)
    col = client.get_or_create_collection("sbom_kb")

    ids, docs, metas = [], [], []
    with open(corpus_jsonl, "r", encoding="utf-8") as f:
        for line in f:
            c = json.loads(line)
            ids.append(c["id"])
            docs.append(c["text"])
            metas.append({
                "type": c["type"],
                "repo": c["repo"],
                "purl": c.get("purl", ""),
                "ecosystem": c.get("ecosystem", ""),
                **(c.get("meta") or {}),
            })

    if dung_embedding:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            print("Thiếu thư viện: sentence-transformers. Cài bằng: pip install sentence-transformers")
            sys.exit(2)

        model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        emb = model.encode(docs, show_progress_bar=True).tolist()
        col.upsert(ids=ids, documents=docs, metadatas=metas, embeddings=emb)
    else:
        col.upsert(ids=ids, documents=docs, metadatas=metas)

    print("Đã index:", len(ids), "chunk vào:", thu_muc_luu)


def buoc_retrieve(thu_muc_luu: str, cau_hoi: str, dung_embedding: bool = True, k: int = 6) -> None:
    import chromadb
    client = chromadb.PersistentClient(path=thu_muc_luu)
    col = client.get_collection("sbom_kb")

    if dung_embedding:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        qemb = model.encode([cau_hoi]).tolist()
        res = col.query(query_embeddings=qemb, n_results=k)
    else:
        res = col.query(query_texts=[cau_hoi], n_results=k)

    for i, (doc, meta, _id) in enumerate(zip(res["documents"][0], res["metadatas"][0], res["ids"][0]), 1):
        print(f"\n--- KẾT QUẢ {i} | id={_id} | loại={meta.get('type')} | purl={meta.get('purl','')}")
        print(doc[:800])


def chay_tat_ca(args) -> None:
    tao_thu_muc(args.thu_muc_out)

    duong_csv = args.csv or os.path.join(args.thu_muc_out, "packages.csv")
    duong_findings = args.findings or os.path.join(args.thu_muc_out, "findings.json")
    duong_report = args.report or os.path.join(args.thu_muc_out, "report.md")
    duong_corpus = args.corpus or os.path.join(args.thu_muc_out, "corpus.jsonl")

    if args.xem_tom_tat:
        buoc_xem_tom_tat(args.sbom)

    buoc_xuat_csv(args.sbom, duong_csv)
    buoc_lam_giau_osv(duong_csv, duong_findings, che_do=args.che_do_osv)
    buoc_tao_bao_cao_md(duong_findings, duong_report)

    if args.rag:
        buoc_tao_corpus(args.sbom, duong_findings, duong_corpus)
        buoc_index_chroma(duong_corpus, args.thu_muc_chroma, dung_embedding=not args.chroma_nhe)
        if args.cau_hoi:
            buoc_retrieve(args.thu_muc_chroma, args.cau_hoi, dung_embedding=not args.chroma_nhe, k=args.k)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Pipeline 1 file: SBOM (SPDX JSON) -> OSV -> report.md (tuỳ chọn RAG với Chroma)"
    )

    ap.add_argument("--sbom", required=True, help="Đường dẫn file SPDX JSON")
    ap.add_argument("--thu-muc-out", default="./out", help="Thư mục output (mặc định: ./out)")

    ap.add_argument("--xem-tom-tat", action="store_true", help="In tóm tắt SBOM trước khi chạy")

    ap.add_argument("--csv", help="Đường dẫn packages.csv (mặc định: out/packages.csv)")
    ap.add_argument("--findings", help="Đường dẫn findings.json (mặc định: out/findings.json)")
    ap.add_argument("--report", help="Đường dẫn report.md (mặc định: out/report.md)")

    ap.add_argument(
        "--che-do-osv",
        choices=["purl", "thong_minh"],
        default="thong_minh",
        help="Cách query OSV: purl hoặc thong_minh (tách ecosystem+name+version)",
    )

    ap.add_argument("--rag", action="store_true", help="Bật: tạo corpus + index Chroma")
    ap.add_argument("--corpus", help="Đường dẫn corpus.jsonl (mặc định: out/corpus.jsonl)")
    ap.add_argument("--thu-muc-chroma", default="./chroma_store", help="Thư mục lưu Chroma (mặc định: ./chroma_store)")
    ap.add_argument(
        "--chroma-nhe",
        action="store_true",
        help="Chroma query_texts (không cần sentence-transformers embeddings)",
    )
    ap.add_argument("--cau-hoi", help="Nếu có, sẽ retrieve top-k chunk theo câu hỏi này")
    ap.add_argument("--k", type=int, default=6, help="Số kết quả retrieve (top-k)")

    args = ap.parse_args()
    chay_tat_ca(args)


if __name__ == "__main__":
    main()
