import json
import time
from fastapi import APIRouter, UploadFile, File, HTTPException, status
from fastapi.responses import StreamingResponse
from app.models.schema import PresentationPayload
from app.engine.router import LogRouterEngine
from app.engine.graph_builder import GraphBuilderEngine
from app.engine.clustering import build_super_nodes
from app.core import session_store
import polars as pl

router = APIRouter(prefix="/v1", tags=["Analysis Engine"])

@router.post("/analyze", response_model=PresentationPayload, summary="Parse auth/access log and generate forensic topology graph")
async def analyze_log_file(file: UploadFile = File(...)):
    """Uploads raw auth.log or web access.log file, inspects line signatures to auto-detect format,
    routes bytes to corresponding Polars SIMD parser, applies heuristic noise reduction,
    and returns the network topology graph presentation payload.
    Data processed strictly in-memory (ephemeral).
    """
    if not file.filename.endswith((".log", ".txt", ".csv")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file extension. Please upload a standard log or text file (.log, .txt, .csv)."
        )

    start_time = time.time()
    content = await file.read()

    # Route and parse log bytes via Strategy/Registry router engine
    df_unified, total_lines, detected_format = LogRouterEngine.route_and_parse(content)

    # Build presentation graph payload from unified schema events
    payload = GraphBuilderEngine.build_from_unified(
        df_unified=df_unified,
        total_lines=total_lines,
        filename=file.filename,
        start_time=start_time
    )

    return payload


@router.post("/analyze/stream", summary="Parse auth/access log with real-time SSE chunk streaming + Super-Node clustering")
async def analyze_log_file_stream(file: UploadFile = File(...)):
    """Uploads raw log file and streams analysis chunks via Server-Sent Events (SSE).
    Yields data in adaptive-sized line chunks with progress percentage, incremental nodes, and edges.
    The FINAL chunk returns Super-Node clustered topology for lightning-fast initial render.
    The full parsed DataFrame is retained in-memory for drill-down expansion.
    """
    if not file.filename.endswith((".log", ".txt", ".csv")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file extension. Please upload a standard log or text file (.log, .txt, .csv)."
        )

    start_time = time.time()
    session_id = f"vestige_sess_{int(time.time() * 1000)}"

    def sse_event_generator():
        has_yielded = False
        all_dfs = []  # Accumulate parsed DataFrames for session storage

        # Fast line count estimate to select adaptive chunk size
        if hasattr(file.file, "seek"):
            file.file.seek(0, 2)
            file_size = file.file.tell()
            file.file.seek(0)
        else:
            file_size = 0

        estimated_lines = file_size // 100 if file_size > 0 else 0
        if estimated_lines > 50000:
            chunk_size = min(25000, max(5000, estimated_lines // 50))
        elif estimated_lines > 10000:
            chunk_size = 2500
        else:
            chunk_size = 1000

        for df_chunk, chunk_idx, total_chunks, processed_lines, total_lines, format_key in LogRouterEngine.stream_chunks(file.file, chunk_size=chunk_size):
            has_yielded = True
            is_final = (chunk_idx == total_chunks - 1)

            # Accumulate parsed DataFrames for later session storage
            if not df_chunk.is_empty():
                all_dfs.append(df_chunk)

            if is_final:
                # ── FINAL CHUNK: Build Super-Node clustered payload ──────
                elapsed_ms = round((time.time() - start_time) * 1000, 2)

                # Concatenate all accumulated DataFrames
                if all_dfs:
                    df_unified = pl.concat(all_dfs, how="diagonal_relaxed")
                else:
                    df_unified = pl.DataFrame()

                # Store the full DataFrame for drill-down queries
                session_store.store_session(session_id, df_unified)

                # Build hierarchical super-nodes
                super_nodes, super_edges = build_super_nodes(df_unified)

                # Serialize super-nodes as node dicts (SuperNodeModel extends NodeModel)
                super_node_dicts = [sn.model_dump() for sn in super_nodes]
                super_edge_dicts = [se.model_dump() for se in super_edges]

                final_payload = {
                    "chunk_index": chunk_idx,
                    "total_chunks": total_chunks,
                    "processed_lines": processed_lines,
                    "total_lines": total_lines,
                    "progress": 100.0,
                    "nodes": super_node_dicts,
                    "edges": super_edge_dicts,
                    "summary": {
                        "total_nodes": len(super_nodes),
                        "total_edges": len(super_edges),
                        "anomalous_edges_count": sum(
                            1 for e in super_edges if e.is_anomalous
                        ),
                        "high_risk_nodes_count": sum(
                            1 for n in super_nodes if n.risk_score >= 5.0
                        ),
                        "detected_lateral_chains": sum(
                            1 for e in super_edges if e.is_anomalous
                        ),
                    },
                    "is_final": True,
                    "meta": {
                        "session_id": session_id,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "log_filename": file.filename,
                        "total_lines_parsed": total_lines,
                        "valid_ssh_events": len(df_unified.filter(pl.col("protocol") == "SSH")) if "protocol" in df_unified.columns else 0,
                        "valid_http_events": len(df_unified.filter(pl.col("protocol") == "HTTP")) if "protocol" in df_unified.columns else 0,
                        "processing_time_ms": elapsed_ms,
                        "noise_reduction_ratio": 0.0,
                    },
                }
                yield f"data: {json.dumps(final_payload)}\n\n"

            else:
                # ── INTERMEDIATE CHUNK: Stream progress metrics ──────────
                chunk_payload = GraphBuilderEngine.build_chunk_payload(
                    df_unified=df_chunk,
                    chunk_idx=chunk_idx,
                    total_chunks=total_chunks,
                    processed_lines=processed_lines,
                    total_lines=total_lines,
                    is_final=False,
                    filename=file.filename,
                    start_time=start_time
                )
                data_json = chunk_payload.model_dump_json()
                yield f"data: {data_json}\n\n"

        if not has_yielded:
            empty_payload = {
                "chunk_index": 0,
                "total_chunks": 1,
                "processed_lines": 0,
                "total_lines": 0,
                "progress": 100.0,
                "nodes": [],
                "edges": [],
                "summary": {
                    "total_nodes": 0,
                    "total_edges": 0,
                    "anomalous_edges_count": 0,
                    "high_risk_nodes_count": 0,
                    "detected_lateral_chains": 0
                },
                "is_final": True,
                "meta": {
                    "session_id": session_id,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "log_filename": file.filename,
                    "total_lines_parsed": 0,
                    "valid_ssh_events": 0,
                    "valid_http_events": 0,
                    "processing_time_ms": 0.0,
                    "noise_reduction_ratio": 0.0,
                },
            }
            yield f"data: {json.dumps(empty_payload)}\n\n"

    return StreamingResponse(sse_event_generator(), media_type="text/event-stream")


