#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, pathlib, re, shutil, subprocess, time, zipfile

ROOT_NAME = "PCG_PCF_papers_2016-2026_2026-07-30"
REPO = pathlib.Path(__file__).resolve().parents[1]
SRC = pathlib.Path(__file__).resolve().parent
OUTDIR = REPO / "output"
WORK = REPO / "bundle"
ROOT = WORK / ROOT_NAME

for p in (OUTDIR, WORK):
    if p.exists(): shutil.rmtree(p)
for d in ("01_direct_pcg_pcf", "02_security_and_cryptanalysis", "03_key_precursors", "04_unavailable_fulltext"):
    (ROOT / d).mkdir(parents=True, exist_ok=True)
OUTDIR.mkdir(parents=True, exist_ok=True)

rows=[]
for mf in sorted(SRC.glob("manifest-*.tsv")):
    with mf.open(encoding="utf-8", newline="") as f:
        rows.extend(csv.DictReader(f, delimiter="\t"))
if len(rows) != 38:
    raise SystemExit(f"expected 38 manifest records, got {len(rows)}")

def run_ok(args:list[str]) -> bool:
    return subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def valid_pdf(p:pathlib.Path) -> tuple[bool,int]:
    try:
        data=p.read_bytes()
        if len(data)<20000 or b"%PDF-" not in data[:1024] or b"<html" in data[:4096].lower(): return False,0
        if not run_ok(["pdfinfo",str(p)]) or not run_ok(["qpdf","--check",str(p)]): return False,0
        text=subprocess.check_output(["pdfinfo",str(p)], text=True, errors="replace")
        m=re.search(r"^Pages:\s*(\d+)",text,re.M)
        return True, int(m.group(1)) if m else 0
    except Exception:
        return False,0

cypher_cache:dict[tuple[str,str],list[str]]={}
def cypherpunks_versions(y:str,n:str) -> list[str]:
    key=(y,n)
    if key in cypher_cache:
        return cypher_cache[key]
    base=f"https://www.eprint.mirror.cypherpunks.su/{y}/{n}/"
    cmd=["curl","-L","-f","-sS","--retry","1","--connect-timeout","15","--max-time","45","-A","Mozilla/5.0",base]
    try:
        html=subprocess.check_output(cmd,text=True,errors="replace")
        names=set(re.findall(r'href=["\']([0-9]+\.pdf)["\']',html,re.I))
        urls=[base+name for name in sorted(names,key=lambda x:int(x[:-4]),reverse=True)]
    except Exception:
        urls=[]
    cypher_cache[key]=urls
    return urls

def candidate_urls(r:dict[str,str]) -> list[str]:
    urls=[u for u in r["extra_urls"].split(";;") if u]
    m=re.fullmatch(r"ePrint (\d{4})/(\d+)",r["identifier"])
    if m:
        y,n=m.groups()
        urls += cypherpunks_versions(y,n)
        urls += [
            f"https://eprint.iacr.org/{y}/{n}.pdf",
            f"https://ia.cr/{y}/{n}.pdf",
            f"https://raw.githubusercontent.com/ShallMate/IACR-eprint-mirror/master/{y}/{n}.pdf",
        ]
    return list(dict.fromkeys(urls))

def download(url:str,dest:pathlib.Path) -> bool:
    tmp=dest.with_suffix(dest.suffix+".part")
    tmp.parent.mkdir(parents=True,exist_ok=True)
    tmp.unlink(missing_ok=True)
    cmd=["curl","-L","-f","-sS","--retry","1","--retry-delay","1","--retry-all-errors",
         "--connect-timeout","15","--max-time","90","-A","Mozilla/5.0","-H","Accept: application/pdf,application/octet-stream;q=0.9,*/*;q=0.8","-o",str(tmp),url]
    if subprocess.run(cmd).returncode==0:
        ok,_=valid_pdf(tmp)
        if ok:
            tmp.replace(dest)
            return True
    tmp.unlink(missing_ok=True)
    return False

validation=[]
for r in rows:
    rid,title=r["id"],r["title"]
    rel=r["relpath"]
    dest=ROOT/rel
    urls=candidate_urls(r)
    status="FAILED"; source=""; pages=0; size=0
    if r["identifier"].startswith("No public") or rel.endswith(".txt"):
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(
            f"Title: {title}\nVenue: {r['venue']} {r['year']}\nAuthors: {r['authors']}\nStatus checked: 2026-07-30\n\n"
            "No public full manuscript was located. Author publication pages listed the work as accepted/to appear but did not expose a downloadable manuscript at the cutoff date.\n\n"
            "Checked pages:\n- https://geoffroycouteau.github.io/\n- https://mahshidriahinia.github.io/\n\n"
            "This is intentionally a text placeholder, not a fabricated PDF.\n",encoding="utf-8")
        status="NOT_PUBLIC"
    else:
        for u in urls:
            print(f"[{rid}] {title}: {u}",flush=True)
            if download(u,dest):
                source=u; status="DOWNLOADED"; size=dest.stat().st_size; pages=valid_pdf(dest)[1]; break
        if status!="DOWNLOADED":
            note=dest.with_name(dest.stem+"_NOT_DOWNLOADED.txt")
            note.write_text(f"Title: {title}\nIdentifier: {r['identifier']}\nStatus: no attempted public URL produced a validated PDF\n\n"+"\n".join(f"- {u}" for u in urls)+"\n",encoding="utf-8")
            rel=str(note.relative_to(ROOT))
    validation.append({"id":rid,"category":r["category"],"venue":r["venue"],"year":r["year"],"title":title,"status":status,"pages":pages,"bytes":size,"source":source,"relative_path":rel})

fields=list(rows[0].keys())
with (ROOT/"papers.tsv").open("w",encoding="utf-8",newline="") as f:
    w=csv.DictWriter(f,fieldnames=fields,delimiter="\t"); w.writeheader(); w.writerows(rows)
with (ROOT/"papers.csv").open("w",encoding="utf-8",newline="") as f:
    w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
(ROOT/"papers.json").write_text(json.dumps(rows,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
with (ROOT/"VALIDATION.tsv").open("w",encoding="utf-8",newline="") as f:
    w=csv.DictWriter(f,fieldnames=validation[0].keys(),delimiter="\t"); w.writeheader(); w.writerows(validation)
(ROOT/"validation.json").write_text(json.dumps(validation,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")

bib=[]
for r in rows:
    key=re.sub(r"[^A-Za-z0-9]+","",r["id"]+r["venue"]+r["year"]).lower()
    authors=" and ".join(x.strip() for x in r["authors"].split(";"))
    m=re.fullmatch(r"ePrint (\d{4})/(\d+)",r["identifier"])
    url=f"https://eprint.iacr.org/{m.group(1)}/{m.group(2)}" if m else next(iter(candidate_urls(r)),"")
    et="misc" if m or r["category"]=="security" else "inproceedings"
    fs=[f"  author = {{{authors}}}",f"  title = {{{r['title']}}}",f"  year = {{{r['year']}}}"]
    fs.append(f"  howpublished = {{{r['identifier']}}}" if et=="misc" else f"  booktitle = {{{r['venue']}}}")
    if url: fs.append(f"  url = {{{url}}}")
    bib.append("@"+et+"{"+key+",\n"+",\n".join(fs)+"\n}")
(ROOT/"references.bib").write_text("\n\n".join(bib)+"\n",encoding="utf-8")

n_ok=sum(v["status"]=="DOWNLOADED" for v in validation)
missing=[v for v in validation if v["status"]!="DOWNLOADED"]
readme=f'''# PCG / PCF 论文归档（2016-01-01 至 2026-07-30）\n\n收录 28 个直接 PCG/PCF 条目、6 篇安全与密码分析论文，以及 4 篇关键前驱，共 38 个元数据条目。\n\n本次构建得到 **{n_ok} 个经验证 PDF**，其余 {len(missing)} 个条目保留明确的未公开/未下载说明。`VALIDATION.tsv` 记录每个文件的页数、字节数和实际来源；`SHA256SUMS.txt` 提供完整性校验。\n\n目录：`01_direct_pcg_pcf/`、`02_security_and_cryptanalysis/`、`03_key_precursors/`、`04_unavailable_fulltext/`。另附 TSV/CSV/JSON、BibTeX、安全状态说明和构建信息。\n\n版本更新：原列为“Fast PCGs for Batch-Authenticated Multiplication Triples”的 CRYPTO 2026 工作已以 ePrint 2026/257 公开，当前题名为“Dishonest-Majority Secure Computation via PIR-Authenticated Multiplication Triples”；本包收录公开版。`Succinct Two-Round Two-Party Signing from PCFs` 截止日仍无公开全文。\n'''
(ROOT/"README_CN.md").write_text(readme,encoding="utf-8")
security='''# 安全状态\n\n1. CRYPTO 2021 Silver 的具体结构化 LDPC 构造已被 CRYPTO 2023 Expand-Convolute 的攻击否定，不应继续作为安全实例。\n2. ePrint 2025/892 对 QA-SD/FOLEAGE 及相关公开参数给出实用攻击；原参数不能直接沿用。\n3. EUROCRYPT 2026 的 Goldreich-PRG 攻击破坏了 EUROCRYPT 2024 public-key silent OT 使用的一个具体实例；应采用修订版本并重新选参。\n4. Ring-LPN 与 Z_{2^k}-LPN 必须使用 ring-aware estimator 重新评估，不能机械套用域上 LPN 参数。\n5. 这些结论通常针对具体实例、参数或证明，不等于否定 PCG/PCF 抽象本身。\n'''
(ROOT/"SECURITY_STATUS_CN.md").write_text(security,encoding="utf-8")
(ROOT/"BUILD_SUMMARY_CN.md").write_text("# 构建结果\n\n"+f"- 已验证 PDF：{n_ok}\n- 未下载/未公开：{len(missing)}\n\n"+"\n".join(f"- {v['id']} {v['title']}: {v['status']}" for v in missing)+"\n",encoding="utf-8")
(ROOT/"BUILD_INFO.txt").write_text(f"Build UTC: {time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}\nCommit: {os.getenv('GITHUB_SHA','local')}\nRun: {os.getenv('GITHUB_RUN_ID','local')}\n",encoding="utf-8")

hashes=[]
for p in sorted(ROOT.rglob("*.pdf")):
    ok,_=valid_pdf(p)
    if not ok: raise SystemExit(f"final PDF validation failed: {p}")
    hashes.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT)}")
(ROOT/"SHA256SUMS.txt").write_text("\n".join(hashes)+"\n",encoding="utf-8")

zip_path=OUTDIR/f"{ROOT_NAME}.zip"
with zipfile.ZipFile(zip_path,"w",zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for p in sorted(ROOT.rglob("*")):
        if p.is_file(): z.write(p,p.relative_to(WORK))
with zipfile.ZipFile(zip_path) as z:
    bad=z.testzip()
    if bad: raise SystemExit(f"zip CRC failure: {bad}")
print(f"ARCHIVE={zip_path} PDFs={n_ok} missing={len(missing)} bytes={zip_path.stat().st_size}")
