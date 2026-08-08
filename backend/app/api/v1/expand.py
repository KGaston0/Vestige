"""
Drill-Down Expansion Endpoint for Super-Node clusters.

GET /api/v1/expand/{session_id}/{super_node_id}

Retrieves the retained in-memory DataFrame for the session, runs the
clustering engine's expand_super_node() to extract child nodes/edges
for the requested cluster, and returns them as an ExpandResponse.
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
    queries the in-memory Polars DataFrame retained from the initial analysis,
    and returns the detailed individual nodes and edges belonging to that cluster.
    """
    df = session_store.get_session(session_id)
    if df is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found or has expired. "
                   f"Please re-upload and analyze the log file.",
        )

    result = expand_super_node(super_node_id=super_node_id, df_unified=df)

    if not result.nodes and not result.edges:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Super-Node '{super_node_id}' has no child nodes in this session. "
                   f"The cluster may be empty or the ID may be incorrect.",
        )

    return result
