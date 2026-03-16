from __future__ import annotations

import json
from html import escape

from mapa.model import MapaProgramString, MapaReport
from mapa.renderer import _visible_tags, render_function_summary_text


def _to_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":")).replace("</", "<\\/")


def _collect_tag_entries(report: MapaReport) -> list[tuple[str, list[int]]]:
    function_index_by_address = {
        function.address: index for index, function in enumerate(report.functions)
    }
    tag_to_functions: dict[str, set[int]] = {}
    for program_string in report.program_strings:
        visible_tags = _visible_tags(program_string.tags)
        if not visible_tags:
            continue
        function_indices = {
            function_index_by_address[address]
            for address in program_string.function_addresses
            if address in function_index_by_address
        }
        if not function_indices:
            continue
        for tag in visible_tags:
            tag_to_functions.setdefault(tag, set()).update(function_indices)

    return sorted(
        (
            (tag, sorted(function_indices))
            for tag, function_indices in tag_to_functions.items()
        ),
        key=lambda item: (-len(item[1]), item[0]),
    )


def _render_string_row(program_string: MapaProgramString, index: int) -> str:
    visible_tags = _visible_tags(program_string.tags)
    tag_text = " ".join(visible_tags)
    tag_span = ""
    if tag_text:
        tag_span = (
            f'<span class="string-tags">{escape(tag_text)}</span>'
        )

    return (
        f'<button type="button" class="string-row" data-string-index="{index}" '
        f'data-string-address="{escape(hex(program_string.address), quote=True)}" '
        f'data-string-value="{escape(program_string.value, quote=True)}" '
        f'data-string-tags="{escape(tag_text, quote=True)}">'
        f'<span class="string-address">{escape(hex(program_string.address))}</span>'
        f'<span class="string-value">{escape(program_string.value)}</span>'
        f"{tag_span}"
        "</button>"
    )


def render_html_map(report: MapaReport) -> str:
    tag_entries = _collect_tag_entries(report)
    function_index_by_address = {
        function.address: index for index, function in enumerate(report.functions)
    }
    program_strings = sorted(report.program_strings, key=lambda string: string.address)

    data = {
        "functions": [
            render_function_summary_text(function) for function in report.functions
        ],
        "tags": {tag: function_indices for tag, function_indices in tag_entries},
        "strings": [
            {
                "address": hex(program_string.address),
                "value": program_string.value,
                "functionIndices": [
                    function_index_by_address[address]
                    for address in program_string.function_addresses
                    if address in function_index_by_address
                ],
            }
            for program_string in program_strings
        ],
    }

    parts: list[str] = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>{escape(report.meta.name)} - MAPA html map</title>",
        "<style>",
        "*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}",
        "html,body{height:100%}",
        ":root{--bg:#fff;--fg:#111;--muted:#666;--line:#cfcfcf;--fill:#d9d9d9;--tag:#2563eb;--string:#93c5fd;--square:10px}",
        "body{height:100vh;overflow:hidden;background:var(--bg);color:var(--fg);font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:16px}",
        "body.is-resizing{cursor:col-resize}",
        "body.is-resizing *{user-select:none}",
        "main{height:100%;min-height:0;display:flex;flex-direction:column;gap:16px}",
        "section{display:flex;flex-direction:column;gap:8px}",
        ".meta,.legend,.pane-header{color:var(--muted)}",
        ".controls{display:flex;flex-wrap:wrap;gap:6px}",
        ".control{border:1px solid var(--line);background:transparent;color:inherit;padding:2px 6px;font:inherit;cursor:pointer}",
        ".control.is-active{border-color:var(--tag);color:var(--tag)}",
        ".control-count{color:var(--muted)}",
        ".split-view{flex:1;min-height:0;display:flex;align-items:stretch}",
        ".pane{min-height:0;display:flex;flex-direction:column;overflow:auto;border:1px solid var(--line);background:var(--bg)}",
        ".pane-functions{flex:0 0 50%;min-width:18rem}",
        ".pane-strings{flex:1 1 auto;min-width:18rem}",
        ".pane-header{position:sticky;top:0;z-index:1;background:var(--bg);border-bottom:1px solid var(--line);padding:8px 10px}",
        ".pane-body{display:flex;flex-direction:column;gap:8px;padding:8px 10px}",
        ".splitter{position:relative;flex:0 0 12px;cursor:col-resize;touch-action:none}",
        ".splitter::before{content:'';position:absolute;top:0;bottom:0;left:50%;width:1px;background:var(--line);transform:translateX(-50%)}",
        ".splitter::after{content:'';position:absolute;top:50%;left:50%;width:3px;height:40px;border-left:1px solid var(--line);border-right:1px solid var(--line);transform:translate(-50%,-50%)}",
        ".function-grid{display:flex;flex-wrap:wrap;gap:1px;align-content:flex-start}",
        ".function-box{width:var(--square);height:var(--square);border:1px solid var(--line);background:var(--fill)}",
        ".function-box.is-tag{border-color:var(--tag)}",
        ".function-box.is-string{background:var(--string)}",
        ".function-box.is-dim{opacity:.5}",
        ".string-list{display:flex;flex-direction:column;gap:2px}",
        ".string-row{display:flex;align-items:flex-start;gap:8px;width:100%;border:1px solid transparent;background:transparent;color:inherit;padding:3px 4px;font:inherit;text-align:left;cursor:pointer}",
        ".string-row:hover,.string-row.is-active{border-color:var(--line)}",
        ".string-address{color:var(--muted);white-space:nowrap;flex:0 0 auto}",
        ".string-value{min-width:0;flex:1 1 auto;white-space:pre-wrap;word-break:break-word}",
        ".string-tags{margin-left:auto;flex:0 0 auto;padding-left:8px;color:var(--muted);white-space:nowrap}",
        ".tooltip{position:fixed;z-index:10;display:none;width:min(42rem,calc(100vw - 24px));max-height:calc(100vh - 24px);overflow:auto;border:1px solid var(--line);background:#fff;padding:8px;pointer-events:none;white-space:pre-wrap;box-shadow:0 2px 8px rgba(0,0,0,.08)}",
        ".tooltip.is-visible{display:block}",
        "h1,h2{font-size:inherit}",
        "</style>",
        "</head>",
        "<body>",
        "<main>",
        "<section>",
        f"<div>{escape(report.meta.name)}</div>",
        (
            f'<div class="meta">sha256 {escape(report.meta.sha256)} · arch {escape(report.meta.arch)}'
            f" · functions {len(report.functions)} · strings {len(program_strings)} · tags {len(tag_entries)}</div>"
        ),
        "<h1>tags</h1>",
        '<div class="controls" id="tag-controls">',
    ]

    for tag, function_indices in tag_entries:
        parts.append(
            (
                f'<button type="button" class="control tag-control" data-tag="{escape(tag, quote=True)}" '
                f'data-count="{len(function_indices)}">{escape(tag)} '
                f'<span class="control-count">({len(function_indices)})</span></button>'
            )
        )

    parts.extend(
        [
            "</div>",
            '<div class="legend">border = tag · fill = string · dim = matches neither</div>',
            "</section>",
            '<div class="split-view" id="split-view">',
            '<section class="pane pane-functions" id="functions-pane">',
            f'<div class="pane-header">functions ({len(report.functions)})</div>',
            '<div class="pane-body">',
            '<div class="function-grid" id="function-grid">',
        ]
    )

    for index, function in enumerate(report.functions):
        parts.append(
            (
                f'<div class="function-box" data-function-index="{index}" '
                f'data-function-address="{escape(hex(function.address), quote=True)}" '
                f'aria-label="{escape(function.name, quote=True)}"></div>'
            )
        )

    parts.extend(
        [
            "</div>",
            "</div>",
            "</section>",
            '<div class="splitter" id="splitter" role="separator" aria-orientation="vertical" aria-label="resize panes"></div>',
            '<section class="pane pane-strings" id="strings-pane">',
            f'<div class="pane-header">strings ({len(program_strings)})</div>',
            '<div class="pane-body">',
            '<div class="string-list" id="string-list">',
        ]
    )

    for index, program_string in enumerate(program_strings):
        parts.append(_render_string_row(program_string, index))

    parts.extend(
        [
            "</div>",
            "</div>",
            "</section>",
            "</div>",
            "</main>",
            '<div class="tooltip" id="tooltip"></div>',
            f'<script type="application/json" id="mapa-data">{_to_json(data)}</script>',
            "<script>",
            "const data=JSON.parse(document.getElementById('mapa-data').textContent);",
            "const splitView=document.getElementById('split-view');",
            "const functionsPane=document.getElementById('functions-pane');",
            "const splitter=document.getElementById('splitter');",
            "const functionBoxes=[...document.querySelectorAll('.function-box')];",
            "const tagControls=[...document.querySelectorAll('.tag-control')];",
            "const stringRows=[...document.querySelectorAll('.string-row')];",
            "const tooltip=document.getElementById('tooltip');",
            "let hoveredTag=null;",
            "let lockedTag=null;",
            "let hoveredString=null;",
            "let lockedString=null;",
            "let activePointerId=null;",
            "const getActiveTag=()=>lockedTag??hoveredTag;",
            "const getActiveString=()=>lockedString??hoveredString;",
            "const updateView=()=>{",
            "  const activeTag=getActiveTag();",
            "  const activeString=getActiveString();",
            "  const tagMatches=new Set(activeTag?data.tags[activeTag]||[]:[]);",
            "  const stringMatches=new Set(activeString===null?[]:data.strings[activeString].functionIndices);",
            "  const hasActive=activeTag!==null||activeString!==null;",
            "  functionBoxes.forEach((box,index)=>{",
            "    const isTag=tagMatches.has(index);",
            "    const isString=stringMatches.has(index);",
            "    box.classList.toggle('is-tag',isTag);",
            "    box.classList.toggle('is-string',isString);",
            "    box.classList.toggle('is-dim',hasActive && !(isTag || isString));",
            "  });",
            "  tagControls.forEach((control)=>{",
            "    control.classList.toggle('is-active',control.dataset.tag===activeTag);",
            "  });",
            "  stringRows.forEach((row)=>{",
            "    row.classList.toggle('is-active',Number(row.dataset.stringIndex)===activeString);",
            "  });",
            "};",
            "const placeTooltip=(event)=>{",
            "  const offset=12;",
            "  let left=event.clientX+offset;",
            "  let top=event.clientY+offset;",
            "  const rect=tooltip.getBoundingClientRect();",
            "  if(left+rect.width>window.innerWidth-8){left=Math.max(8,window.innerWidth-rect.width-8);}",
            "  if(top+rect.height>window.innerHeight-8){top=Math.max(8,window.innerHeight-rect.height-8);}",
            "  tooltip.style.left=`${left}px`;",
            "  tooltip.style.top=`${top}px`;",
            "};",
            "const getPaneMinWidth=()=>parseFloat(getComputedStyle(document.documentElement).fontSize)*18;",
            "const resizePanes=(clientX)=>{",
            "  const rect=splitView.getBoundingClientRect();",
            "  const splitterWidth=splitter.getBoundingClientRect().width;",
            "  const paneMinWidth=getPaneMinWidth();",
            "  const minLeft=rect.left+paneMinWidth;",
            "  const maxLeft=rect.right-paneMinWidth-splitterWidth;",
            "  if(maxLeft<=minLeft){functionsPane.style.flexBasis='50%';return;}",
            "  const clampedLeft=Math.min(maxLeft,Math.max(minLeft,clientX));",
            "  functionsPane.style.flexBasis=`${clampedLeft-rect.left}px`;",
            "};",
            "const clampPaneSize=()=>{",
            "  const basis=parseFloat(functionsPane.style.flexBasis);",
            "  if(Number.isFinite(basis)){resizePanes(splitView.getBoundingClientRect().left+basis);}",
            "};",
            "const stopResizing=(event)=>{",
            "  if(activePointerId===null||event.pointerId!==activePointerId){return;}",
            "  if(splitter.hasPointerCapture(event.pointerId)){splitter.releasePointerCapture(event.pointerId);}",
            "  activePointerId=null;",
            "  document.body.classList.remove('is-resizing');",
            "};",
            "functionBoxes.forEach((box,index)=>{",
            "  box.addEventListener('mouseenter',(event)=>{",
            "    tooltip.textContent=data.functions[index];",
            "    tooltip.classList.add('is-visible');",
            "    placeTooltip(event);",
            "  });",
            "  box.addEventListener('mousemove',placeTooltip);",
            "  box.addEventListener('mouseleave',()=>{tooltip.classList.remove('is-visible');});",
            "});",
            "tagControls.forEach((control)=>{",
            "  control.addEventListener('mouseenter',()=>{if(lockedTag===null){hoveredTag=control.dataset.tag;updateView();}});",
            "  control.addEventListener('mouseleave',()=>{if(lockedTag===null){hoveredTag=null;updateView();}});",
            "  control.addEventListener('click',()=>{lockedTag=lockedTag===control.dataset.tag?null:control.dataset.tag;hoveredTag=null;updateView();});",
            "});",
            "stringRows.forEach((row)=>{",
            "  row.addEventListener('mouseenter',()=>{if(lockedString===null){hoveredString=Number(row.dataset.stringIndex);updateView();}});",
            "  row.addEventListener('mouseleave',()=>{if(lockedString===null){hoveredString=null;updateView();}});",
            "  row.addEventListener('click',()=>{const index=Number(row.dataset.stringIndex);lockedString=lockedString===index?null:index;hoveredString=null;updateView();});",
            "});",
            "splitter.addEventListener('pointerdown',(event)=>{",
            "  activePointerId=event.pointerId;",
            "  splitter.setPointerCapture(event.pointerId);",
            "  document.body.classList.add('is-resizing');",
            "  resizePanes(event.clientX);",
            "  event.preventDefault();",
            "});",
            "splitter.addEventListener('pointermove',(event)=>{if(activePointerId===event.pointerId){resizePanes(event.clientX);}});",
            "splitter.addEventListener('pointerup',stopResizing);",
            "splitter.addEventListener('pointercancel',stopResizing);",
            "window.addEventListener('resize',clampPaneSize);",
            "updateView();",
            "</script>",
            "</body>",
            "</html>",
        ]
    )

    return "\n".join(parts)
