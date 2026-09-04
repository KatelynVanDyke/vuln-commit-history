from __future__ import annotations

from collections import Counter

ACTION_KINDS = {"insert-node", "insert-tree", "delete-node", "delete-tree", "update-node", "move-tree"}

ROOT_PARENT = "ROOT"


def _node_type(line: str) -> str:
    stripped = line.strip()
    colon = stripped.find(":")
    bracket = stripped.rfind("[")
    if colon != -1 and (bracket == -1 or colon < bracket):
        return stripped[:colon].strip()
    if bracket != -1:
        return stripped[:bracket].strip()
    return stripped


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _split_blocks(textdiff_output: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in textdiff_output.splitlines():
        if line == "===":
            if current is not None:
                blocks.append(current)
            current = []
            continue
        if current is not None:
            current.append(line)
    if current:
        blocks.append(current)
    return blocks


def _classify_subtree_action(kind: str, body: list[str], counts: Counter[str]) -> None:
    root_type = _node_type(body[0])
    i = 1
    tree_lines = []
    while i < len(body) and body[i].startswith(" "):
        tree_lines.append(body[i])
        i += 1

    stack: list[tuple[int, str]] = [(-1, root_type)]
    for line in tree_lines:
        depth = _indent(line)
        while len(stack) > 1 and stack[-1][0] >= depth:
            stack.pop()
        parent_type = stack[-1][1]
        child_type = _node_type(line)
        counts[f"{kind}_{child_type}_{parent_type}"] += 1
        stack.append((depth, child_type))

    root_parent_type = ROOT_PARENT
    if i < len(body) and body[i].strip() == "to" and i + 1 < len(body):
        root_parent_type = _node_type(body[i + 1])
    counts[f"{kind}_{root_type}_{root_parent_type}"] += 1


def classify_actions(textdiff_output: str) -> Counter[str]:
    """Coming-shaped {action}_{childType}_{parentType} counts from a GumTree `textdiff` dump."""
    counts: Counter[str] = Counter()
    for block in _split_blocks(textdiff_output):
        if not block:
            continue
        kind, body = block[0], block[2:]
        if kind not in ACTION_KINDS or not body:
            continue

        if kind in ("insert-tree", "delete-tree", "move-tree"):
            _classify_subtree_action(kind, body, counts)
        elif kind == "insert-node":
            child_type = _node_type(body[0])
            parent_type = ROOT_PARENT
            if len(body) >= 3 and body[1].strip() == "to":
                parent_type = _node_type(body[2])
            counts[f"{kind}_{child_type}_{parent_type}"] += 1
        else:  # delete-node, update-node -- GumTree never states a parent for either
            child_type = _node_type(body[0])
            counts[f"{kind}_{child_type}_{ROOT_PARENT}"] += 1

    return counts
