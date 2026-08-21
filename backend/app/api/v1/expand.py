"""
Drill-Down Expansion Endpoint for Super-Node clusters.

GET /api/v1/expand/{session_id}/{super_node_id}

Retrieves a LazyFrame backed by the session's on-disk Parquet file, passes it
to clustering.expand_super_node() which filters only the relevant slice before
collecting, and returns the child nodes/edges as an ExpandResponse.

Spill-to-disk contract
────────────────────────
session_store.get_session() now returns a pl.LazyFrame, so no RAM is allocated
until expand_super_node() runs its targeted .filter().collect() internally.
"""

from fastapi import APIRouter, HTTPException, status

from app.models.schema import ExpandResponse
from app.core import session_store
from app.engine.clustering import expand_super_node

router = APIRouter(prefix="/v1", tags=["Drill-Down Expansion"])


@router.get(
    "/expand/{session_id}/{super_node_id:path}",
    response_model=ExpandResponse,
    summary="Expand a Super-Node cluster into its individual child nodes and edges",
)
async def expand_cluster(session_id: str, super_node_id: str):
    """
    Drill-down endpoint. Takes a session_id (returned in the SSE meta payload)
    and a super_node_id (e.g. 'super:external_threats', 'super:subnet:10.0.4.0/24'),
    queries the on-disk Parquet file retained from the initial analysis via a
    zero-RAM LazyFrame, and returns the detailed individual nodes and edges
    belonging to that cluster.
    """
    # Returns pl.LazyFrame or None — no data loaded yet
    lf = session_store.get_session(session_id)
    if lf is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found or has expired. "
                   f"Please re-upload and analyze the log file.",
        )

    # expand_super_node accepts LazyFrame; it filters and collects internally
    result = expand_super_node(super_node_id=super_node_id, df_unified=lf)

    if not result.nodes and not result.edges:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Super-Node '{super_node_id}' has no child nodes in this session. "
                   f"The cluster may be empty or the ID may be incorrect.",
        )

    return result
