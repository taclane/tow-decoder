#!/usr/bin/env python3
"""
Decoder for The Outer Worlds (1)'s `SerializedConversationData` binary blob

The format was reverse-engineered with the assistance of Ghidra, and checked
byte-for-byte against the whole 961-file conversation set of the "Spacers's Choice"
edition.

Every file parses, every byte is accounted for.

Run with -h for usage.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import Any

__version__ = "2.1.0"

NODE_TYPE = {
    0: "Talk",
    1: "PlayerResponse",
    2: "Script",
    3: "TriggerConversation",
    4: "Chatter",
    5: "Bank",
    6: "Quest",
    7: "Objective",
    8: "EndState",
    9: "GlobalQuest",
    10: "BranchComplete",
    11: "ChatterEvent",
    12: "SoundEffect",
}

# Does this node type extend FDialogueNode (gets the DialogueNode tail) or FFlowChartNode
# directly (skips it)? Confirmed from each class's own Serialize() base-class call.
EXTENDS_DIALOGUE_NODE = {
    0: True,  # Talk
    1: True,  # PlayerResponse
    2: True,  # Script
    3: True,  # TriggerConversation
    4: True,  # Chatter
    5: False,  # Bank
    6: False,  # Quest
    7: False,  # Objective
    8: False,  # EndState
    9: False,  # GlobalQuest -- assumed; no Serialize override was found for this class
    10: False,  # BranchComplete
    11: True,  # ChatterEvent
    12: True,  # SoundEffect
}


class ParseError(ValueError):
    """Raised when a byte stream doesn't match this format -- always includes the byte offset."""


class R:
    """Little-endian byte-cursor reader over the raw `SerializedConversationData` bytes."""

    __slots__ = ("b", "i")

    def __init__(self, b: bytes) -> None:
        self.b = b
        self.i = 0

    def u8(self) -> int:
        v = self.b[self.i]
        self.i += 1
        return v

    def i32(self) -> int:
        v = struct.unpack_from("<i", self.b, self.i)[0]
        self.i += 4
        return v

    def f32(self) -> float:
        v = struct.unpack_from("<f", self.b, self.i)[0]
        self.i += 4
        return v

    def guid(self) -> str:
        """4x little-endian uint32 groups, dash-joined uppercase hex. Not a standard
        8-4-4-4-12 GUID; use `canon_guid()` to convert."""
        parts = struct.unpack_from("<IIII", self.b, self.i)
        self.i += 16
        return "-".join(f"{p:08X}" for p in parts)

    def fstr(self) -> str:
        n = self.i32()
        if n == 0:
            return ""
        if not (0 < n < 10000):
            raise ParseError(f"implausible fstring length {n} @ {self.i - 4}")
        s = self.b[self.i : self.i + n]
        self.i += n
        return s[:-1].decode("latin1") if s.endswith(b"\x00") else s.decode("latin1")

    def bool4(self) -> bool:
        return self.i32() != 0

    def tag(self) -> int:
        """Per-class version byte. Read but not checked; see module docstring."""
        return self.u8()


def canon_guid(raw: str) -> str:
    """Convert this format's guid printing to a standard, lowercase 8-4-4-4-12 GUID string.
    A re-slice of the same 32 hex digits, not a byte-order change."""
    hexdigits = raw.replace("-", "").lower()
    return f"{hexdigits[0:8]}-{hexdigits[8:12]}-{hexdigits[12:16]}-{hexdigits[16:20]}-{hexdigits[20:32]}"


# ---------------------------------------------------------------------------------------------
# Conditionals / script calls
# ---------------------------------------------------------------------------------------------


def read_expr_component(r: R) -> int:
    r.tag()
    return r.u8()  # Operator: 0=And, 1=Or -- joins this component to its next sibling


def read_conditional(r: R, depth: int = 0) -> dict[str, Any]:
    if depth > 20:
        raise ParseError("conditional recursion too deep -- probable desync")
    op = read_expr_component(r)
    r.tag()
    count = r.i32()
    if not (0 <= count < 1000):
        raise ParseError(f"implausible Components count {count} @ {r.i - 4}")
    components = []
    for _ in range(count):
        ctype = r.u8()
        if ctype == 0:
            components.append(read_conditional_call(r))
        elif ctype == 1:
            components.append(read_conditional(r, depth + 1))
        else:
            raise ParseError(f"unknown component type {ctype} @ {r.i - 1}")
    return {"Operator": op, "Components": components}


def read_conditional_call(r: R) -> dict[str, Any]:
    op = read_expr_component(r)
    r.tag()
    not_ = r.bool4()
    script_call = r.fstr()
    full_name = r.fstr()
    flags = r.fstr()
    params_count = r.i32()
    if not (0 <= params_count < 100):
        raise ParseError(f"implausible Parameters count {params_count} @ {r.i - 4}")
    params = [r.fstr() for _ in range(params_count)]
    return {
        "Operator": op,
        "Not": not_,
        "ScriptCall": script_call,
        "FullName": full_name,
        "Flags": flags,
        "Parameters": params,
    }


def read_script_call(r: R) -> dict[str, Any]:
    r.tag()
    script = r.fstr()
    flags = r.fstr()
    cond = read_conditional(r)
    return {"Script": script, "Flags": flags, "Conditional": cond}


def read_script_calls_array(r: R) -> list[dict[str, Any]]:
    count = r.i32()
    if not (0 <= count < 500):
        raise ParseError(f"implausible script call array count {count} @ {r.i - 4}")
    return [read_script_call(r) for _ in range(count)]


# ---------------------------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------------------------


def read_link_base(r: R) -> tuple[int, int, dict[str, Any]]:
    r.tag()
    frm = r.i32()
    to = r.i32()
    cond = read_conditional(r)
    return frm, to, cond


def read_dialogue_link(r: R) -> dict[str, Any]:
    frm, to, cond = read_link_base(r)
    r.tag()
    rw = r.i32()
    play_q_vo = r.bool4()
    q_display = r.i32()
    return {
        "FromNodeID": frm,
        "ToNodeID": to,
        "Conditional": cond,
        "RandomWeight": rw,
        "PlayQuestionNodeVO": play_q_vo,
        "QuestionNodeTextDisplay": q_display,
    }


def read_chatter_link(r: R) -> dict[str, Any]:
    frm, to, cond = read_link_base(r)
    r.tag()
    rw = r.i32()
    return {"FromNodeID": frm, "ToNodeID": to, "Conditional": cond, "RandomWeight": rw}


def read_quest_link(r: R) -> dict[str, Any]:
    frm, to, cond = read_link_base(r)
    r.tag()
    req = r.bool4()
    fails = r.bool4()
    return {
        "FromNodeID": frm,
        "ToNodeID": to,
        "Conditional": cond,
        "IsRequiredToExitObjective": req,
        "FailsObjective": fails,
    }


def read_links_array(r: R) -> list[dict[str, Any]]:
    count = r.i32()
    if not (0 <= count < 500):
        raise ParseError(f"implausible Links count {count} @ {r.i - 4}")
    links = []
    for _ in range(count):
        ltype = r.i32()
        if ltype == 1:
            links.append(read_chatter_link(r))
        elif ltype == 3:
            links.append(read_quest_link(r))
        elif ltype in (0, 2):
            links.append(read_dialogue_link(r))
        else:
            raise ParseError(f"unknown link type {ltype} @ {r.i - 4}")
    return links


# ---------------------------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------------------------


def read_flowchart_node_base(r: R) -> dict[str, Any]:
    r.tag()
    unique_id = r.guid()
    node_id = r.i32()
    container_id = r.i32()
    node_type = r.u8()
    links = read_links_array(r)
    cond = read_conditional(r)
    on_enter = read_script_calls_array(r)
    on_exit = read_script_calls_array(r)
    on_update = read_script_calls_array(r)
    return {
        "UniqueID": unique_id,
        "NodeID": node_id,
        "ContainerNodeID": container_id,
        "NodeType": node_type,
        "Links": links,
        "Conditional": cond,
        "OnEnterScripts": on_enter,
        "OnExitScripts": on_exit,
        "OnUpdateScripts": on_update,
    }


def read_dialogue_node_tail(r: R, base: dict[str, Any]) -> dict[str, Any]:
    base["NotSkippable"] = r.bool4()
    base["IsQuestionNode"] = r.bool4()
    base["HideSpeaker"] = r.bool4()
    base["PlayVOAs3DSound"] = r.bool4()
    base["PlayType"] = r.u8()
    base["Persistence"] = r.u8()
    base["NoPlayRandomWeight"] = r.i32()
    base["DisplayType"] = r.u8()
    base["VOPositioning"] = r.u8()
    return base


def read_quest_end_state(r: R) -> dict[str, Any]:
    """`FQuestEndState::Serialize` was never decompiled. Guessed from an init pattern and a
    16-byte stride; see module docstring."""
    return {"ID": r.i32()}


def read_node_outer(r: R) -> dict[str, Any]:
    # UFlowChart::SerializeParsedData reads NodeID+NodeType before creating the node and
    # calling its Serialize, which reads them again. Confirmed real, not a bug.
    node_id = r.i32()
    node_type_byte = r.u8()
    node_type = NODE_TYPE.get(node_type_byte, f"UNKNOWN({node_type_byte})")
    base = read_flowchart_node_base(r)
    if EXTENDS_DIALOGUE_NODE.get(node_type_byte, True):
        base = read_dialogue_node_tail(r, base)

    if node_type_byte == 0:  # Talk
        r.tag()
        base["SpeakerGameDataID"] = r.guid()
        base["ListenerGameDataID"] = r.guid()
        base["EmotionType"] = r.fstr()
        base["EmotionStrength"] = r.f32()
        base["EmotionDelay"] = r.f32()
        base["ExternalVO"] = r.fstr()
        base["VODelayOverride"] = r.f32()
        base["bOmitFromUIHistory"] = r.bool4()
        base["HasVO"] = r.bool4()
        base["bPersistEmotion"] = r.bool4()
        base["VOAttenuationType"] = r.u8()
        base["VOEstimatedDuration"] = r.f32()
    elif node_type_byte == 1:  # PlayerResponse
        tag = r.tag()
        base["bAppendLeaveConversation"] = r.bool4()
        if tag > 1:
            base["bAppendTrade"] = r.bool4()
        # CacheConditionalParams is a derived step here, not an archive read; consumes no bytes.
    elif node_type_byte == 2:  # Script
        r.tag()
        base["RequiresValidChildNode"] = r.bool4()
    elif node_type_byte == 3:  # TriggerConversation
        r.tag()
        base["ConversationID"] = r.guid()
        base["StartNodeID"] = r.i32()
    elif node_type_byte == 4:  # Chatter
        r.tag()
        base["VariantCount"] = r.i32()
    elif node_type_byte == 5:  # Bank
        r.tag()
        base["PlayType"] = r.i32()
        base["Persistence"] = r.u8()
        n = r.i32()
        base["ChildNodeIDs"] = [r.i32() for _ in range(n)]
    elif node_type_byte == 6:  # Quest
        r.tag()
        base["LinkEvaluation"] = r.i32()
        n = r.i32()
        base["AlternateDescriptionIDs"] = [r.guid() for _ in range(n)]
        base["ExperienceReward"] = r.i32()
        n2 = r.i32()
        base["EndStates"] = [read_quest_end_state(r) for _ in range(n2)]
    elif node_type_byte == 7:  # Objective
        r.tag()
        base["LinkEvaluation"] = r.i32()
        n = r.i32()
        base["AddendumIDs"] = [r.guid() for _ in range(n)]
        n2 = r.i32()
        base["AlternateDescriptionIDs"] = [r.guid() for _ in range(n2)]
        base["ExperienceWeight"] = r.i32()
        base["DisplayType"] = r.i32()
        base["SortGroup"] = r.i32()
    elif node_type_byte == 8:  # EndState
        r.tag()
        base["WillFailQuest"] = r.bool4()
        base["EndStateID"] = r.i32()
    elif node_type_byte == 9:  # GlobalQuest -- no Serialize override found, no extra tail
        pass
    elif node_type_byte == 10:  # BranchComplete
        r.tag()
        base["WillFailObjective"] = r.bool4()
    elif node_type_byte == 11:  # ChatterEvent -- no fields beyond the tag
        r.tag()
    elif node_type_byte == 12:  # SoundEffect
        r.tag()
        base["AudioEvent"] = r.fstr()
        base["FadeOutDuration"] = r.f32()

    base["_outer_NodeID"] = node_id
    base["_outer_NodeType"] = node_type
    return base


# ---------------------------------------------------------------------------------------------
# Trailer (ExtendedProperties + TriggeredConversationIDs + SpeakerGameDataIDs)
# ---------------------------------------------------------------------------------------------


def read_fguid_tset(r: R) -> dict[str, Any]:
    """`TSet<FGuid>`: count-prefixed elements, then a 3-field sparse-array tail
    (FirstFreeIndex, NumFreeIndices, NumBits). NumBits never gates further bytes here;
    see the Trailer section of the module docstring."""
    count = r.i32()
    if not (0 <= count < 10000):
        raise ParseError(f"implausible TSet<FGuid> count {count} @ {r.i - 4}")
    guids = [r.guid() for _ in range(count)]
    first_free_index = r.i32()
    num_free_indices = r.i32()
    num_bits = r.i32()
    return {
        "Guids": guids,
        "FirstFreeIndex": first_free_index,
        "NumFreeIndices": num_free_indices,
        "NumBits": num_bits,
    }


def read_fguid_array(r: R) -> list[str]:
    """`TArray<FGuid>`: a plain count-prefixed array, no TSet-style bookkeeping tail."""
    count = r.i32()
    if not (0 <= count < 10000):
        raise ParseError(f"implausible TArray<FGuid> count {count} @ {r.i - 4}")
    return [r.guid() for _ in range(count)]


def read_trailer(r: R) -> dict[str, Any]:
    r.tag()
    unknown_header_byte = r.u8()  # varies 0-10+ across the corpus; meaning unknown
    prop_count = r.i32()
    if not (0 <= prop_count < 100):
        raise ParseError(f"implausible ExtendedProperties count {prop_count} @ {r.i - 4}")
    extended_properties = {}
    for _ in range(prop_count):
        key = r.fstr()
        value = r.fstr()
        extended_properties[key] = value
    triggered_conversation_ids = read_fguid_tset(r)
    speaker_game_data_ids = read_fguid_array(r)
    unknown_tail = r.bool4()  # observed 0/1 corpus-wide; meaning unknown
    return {
        "_unknown_header_byte": unknown_header_byte,
        "ExtendedProperties": extended_properties,
        "TriggeredConversationIDs": triggered_conversation_ids["Guids"],
        "SpeakerGameDataIDs": speaker_game_data_ids,
        "_unknown_tail": unknown_tail,
    }


# ---------------------------------------------------------------------------------------------
# Top level
# ---------------------------------------------------------------------------------------------


def decode_conversation_bytes(data: bytes, *, canonicalize_guids: bool = True) -> dict[str, Any]:
    """Decode a raw `SerializedConversationData` byte array into a fully JSON-serializable dict.
    Raises `ParseError` (a `ValueError` subclass) on any structural inconsistency."""
    r = R(data)
    version = r.u8()
    top_guid = r.guid()
    loaded_filename = r.fstr()
    string_table_name = r.fstr()
    node_count = r.i32()
    if not (0 <= node_count < 100000):
        raise ParseError(f"implausible node count {node_count} @ {r.i - 4}")
    nodes = [read_node_outer(r) for _ in range(node_count)]
    trailer = read_trailer(r)
    if r.i != len(data):
        raise ParseError(f"did not fully consume buffer: read {r.i} of {len(data)} bytes")

    out = {
        "Version": version,
        "Guid": top_guid,
        "LoadedFilename": loaded_filename,
        "StringTableName": string_table_name,
        "Nodes": nodes,
        "Trailer": trailer,
    }
    if canonicalize_guids:
        out = _canonicalize_guids_in_place(out)
    return out


def _canonicalize_guids_in_place(obj: Any) -> Any:
    """Rewrite every string matching this format's guid convention into a standard GUID.
    Matched by shape, not by field name, since guids appear under many different keys."""
    if isinstance(obj, dict):
        return {k: _canonicalize_guids_in_place(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_canonicalize_guids_in_place(v) for v in obj]
    if (
        isinstance(obj, str)
        and len(obj) == 35
        and obj.count("-") == 3
        and all(c in "0123456789ABCDEF-" for c in obj)
    ):
        return canon_guid(obj)
    return obj


def load_asset_json(path: Path) -> tuple[bytes, dict[str, Any]]:
    """Read a UAsset JSON export and split out the raw `SerializedConversationData` bytes
    from the asset's own top-level metadata (Name, ObsidianID, ConversationFile, ...)."""
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, list) or not raw:
        raise ParseError(f"expected a UAsset-wrapper JSON array: {path}")
    asset = raw[0]
    props = asset.get("Properties", {})
    data = props.get("SerializedConversationData")
    if data is None:
        raise ParseError(f"no SerializedConversationData property: {path}")
    meta = {k: v for k, v in asset.items() if k != "Properties"}
    meta["Properties"] = {k: v for k, v in props.items() if k != "SerializedConversationData"}
    return bytes(data), meta


def decode_asset_file(path: Path, *, canonicalize_guids: bool = True) -> dict[str, Any]:
    """Decode one asset file end to end: read the wrapper JSON, decode the blob, and add the
    asset's own metadata under `Asset`."""
    data, meta = load_asset_json(path)
    decoded = decode_conversation_bytes(data, canonicalize_guids=canonicalize_guids)
    decoded["Asset"] = meta
    return decoded


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------


def _iter_input_files(root: Path, pattern: str) -> list[Path]:
    return sorted(p for p in root.glob(pattern) if p.is_file())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tow_decoder.py",
        description="Decode TOW1 (The Outer Worlds 1) SerializedConversationData asset(s) to JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "input", type=Path, help="a single asset JSON file, or a directory to batch-decode"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="output file for a single input (default: stdout), or output directory root "
        "for a directory input (required; mirrors the input tree)",
    )
    parser.add_argument(
        "--glob",
        default="**/*.json",
        help="directory mode only: glob pattern for input files, relative to the input directory (default: **/*.json)",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indent width (default: 2). Use --compact for minified output",
    )
    parser.add_argument(
        "--compact", action="store_true", help="minified JSON output (overrides --indent)"
    )
    parser.add_argument(
        "--raw-guids",
        action="store_true",
        help="keep this format's raw guid printing instead of canonicalizing to a standard GUID",
    )
    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="directory mode only: stop the batch on the first file that fails to parse "
        "(default: log it to stderr, keep going, and exit non-zero at the end if any failed)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="directory mode only: suppress per-file progress on stderr",
    )
    args = parser.parse_args(argv)

    indent = None if args.compact else args.indent
    canonicalize = not args.raw_guids

    if args.input.is_dir():
        if args.output is None:
            parser.error("directory input requires -o/--output (an output directory)")
        files = _iter_input_files(args.input, args.glob)
        if not files:
            parser.error(f"no files matched {args.glob!r} under {args.input}")
        ok = 0
        failed: list[tuple[Path, str]] = []
        for i, f in enumerate(files, 1):
            rel = f.relative_to(args.input)
            if not args.quiet:
                print(f"[{i}/{len(files)}] {rel}", file=sys.stderr)
            try:
                decoded = decode_asset_file(f, canonicalize_guids=canonicalize)
            except Exception as e:  # noqa: BLE001 -- batch must survive one bad file
                failed.append((rel, str(e)))
                print(f"  FAILED: {e}", file=sys.stderr)
                if args.stop_on_error:
                    return 1
                continue
            out_path = args.output / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(decoded, indent=indent), encoding="utf-8")
            ok += 1
        print(f"\n{ok}/{len(files)} decoded cleanly, {len(failed)} failed", file=sys.stderr)
        for rel, err in failed:
            print(f"  {rel}: {err}", file=sys.stderr)
        return 1 if failed else 0

    # single-file mode
    try:
        decoded = decode_asset_file(args.input, canonicalize_guids=canonicalize)
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}", file=sys.stderr)
        return 1
    text = json.dumps(decoded, indent=indent)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
