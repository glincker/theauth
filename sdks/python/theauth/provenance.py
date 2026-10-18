"""Input provenance transport helpers.

``POST /authorize`` takes ``inputs`` in the body (see
:class:`theauth.types.ProvenanceInput`). Proxies and gateways that cannot rewrite
a body can send the same array in the ``TheAuth-Inputs`` header instead, as
base64url JSON. The server ignores a malformed header and the body wins when both
are present, so prefer entries with a ``hash`` over ``content`` in a header:
proxies log headers.
"""

from __future__ import annotations

import base64
import json
from typing import Dict, Sequence

from theauth.types.authorize import ProvenanceInput

INPUTS_HEADER = "TheAuth-Inputs"
MAX_INPUTS = 32
MAX_HEADER_CHARS = 8192


def encode_inputs_header(inputs: Sequence[ProvenanceInput]) -> str:
    """Header value for ``inputs``: base64url (no padding) of the JSON array.

    Raises:
        ValueError: More than 32 inputs, or a value longer than 8192 characters
            (the server would ignore it).
    """
    if len(inputs) > MAX_INPUTS:
        raise ValueError(f"at most {MAX_INPUTS} inputs fit in the header")
    raw = json.dumps([i.to_dict() for i in inputs], separators=(",", ":"), ensure_ascii=False)
    value = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")
    if len(value) > MAX_HEADER_CHARS:
        raise ValueError(f"encoded inputs are {len(value)} characters, the limit is {MAX_HEADER_CHARS}")
    return value


def inputs_headers(inputs: Sequence[ProvenanceInput]) -> Dict[str, str]:
    """``{"TheAuth-Inputs": ...}``, ready for the ``headers`` argument of a client."""
    return {INPUTS_HEADER: encode_inputs_header(inputs)}
