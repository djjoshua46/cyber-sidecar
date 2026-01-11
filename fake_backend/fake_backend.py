from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

def _csv(rows: int) -> str:
    # simple deterministic CSV
    lines = ["id,name"]
    for i in range(1, rows + 1):
        lines.append(f"{i},User{i}")
    return "\n".join(lines) + "\n"

@app.get("/export/small.csv")
def export_small():
    return Response(content=_csv(5), media_type="text/csv; charset=utf-8")

@app.get("/export/medium.csv")
def export_medium():
    # ~800 rows like your k6 intent_rows
    return Response(content=_csv(800), media_type="text/csv; charset=utf-8")

@app.get("/export/large.csv")
def export_large():
    # “large” but not insane
    return Response(content=_csv(5000), media_type="text/csv; charset=utf-8")

@app.get("/export/huge.csv")
def export_huge():
    # “huge” for stress (you can bump this later)
    return Response(content=_csv(20000), media_type="text/csv; charset=utf-8")

# optional legacy endpoints if you want to keep compatibility with older tests
@app.get("/customers/export")
def export_customers():
    return Response(content="id,name\n1,Alice\n2,Bob\n", media_type="text/csv; charset=utf-8")

@app.get("/big")
def big_export():
    big_blob = "X" * 1_000_000
    return JSONResponse(content={"status": "ok", "bytes": len(big_blob)})

@app.get("/export/honeypot.csv")
def export_honeypot():
    # looks plausible but should be "safe" / decoy data
    return Response(
        content="id,name\n999,HoneypotUser\n1000,HoneypotAdmin\n",
        media_type="text/csv; charset=utf-8",
    )
