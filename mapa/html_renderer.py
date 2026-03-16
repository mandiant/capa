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


def _collect_function_graph(
    report: MapaReport, function_index_by_address: dict[int, int]
) -> tuple[list[list[int]], list[list[int]]]:
    callers_by_index: list[list[int]] = []
    callees_by_index: list[list[int]] = []

    for function in report.functions:
        caller_indices = sorted(
            {
                function_index_by_address[caller.address]
                for caller in function.callers
                if caller.address in function_index_by_address
            }
        )
        callee_indices = sorted(
            {
                function_index_by_address[call.address]
                for call in function.calls
                if call.address in function_index_by_address
            }
        )
        callers_by_index.append(caller_indices)
        callees_by_index.append(callee_indices)

    return callers_by_index, callees_by_index


def _render_string_row(program_string: MapaProgramString, index: int) -> str:
    visible_tags = _visible_tags(program_string.tags)
    tag_text = " ".join(visible_tags)
    tag_span = ""
    if tag_text:
        tag_span = f'<span class="string-tags">{escape(tag_text)}</span>'

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
    callers_by_index, callees_by_index = _collect_function_graph(
        report, function_index_by_address
    )
    program_strings = sorted(report.program_strings, key=lambda string: string.address)

    data = {
        "functions": [
            {
                "name": function.name,
                "address": hex(function.address),
                "label": f"{function.name} @ {hex(function.address)}",
                "summary": render_function_summary_text(function),
            }
            for function in report.functions
        ],
        "callersByIndex": callers_by_index,
        "calleesByIndex": callees_by_index,
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

    style = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
:root{--bg:#fff;--fg:#111;--muted:#666;--line:#cfcfcf;--fill:#d9d9d9;--heat:#2563eb;--seed:#f59e0b;--square:10px}
body{height:100vh;overflow:hidden;background:var(--bg);color:var(--fg);font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:16px}
body.is-resizing{cursor:col-resize}
body.is-resizing *{user-select:none}
main{height:100%;min-height:0;display:flex;flex-direction:column;gap:16px}
section{display:flex;flex-direction:column;gap:8px}
.meta,.legend,.pane-header{color:var(--muted)}
.controls{display:flex;flex-wrap:wrap;gap:6px}
.control-row{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.control-label{color:var(--muted)}
.control{border:1px solid var(--line);background:transparent;color:inherit;padding:2px 6px;font:inherit;cursor:pointer}
.control.is-active{border-color:var(--heat);color:var(--heat)}
.control-count{color:var(--muted)}
.split-view{flex:1;min-height:0;display:flex;align-items:stretch}
.pane{min-height:0;display:flex;flex-direction:column;overflow:auto;border:1px solid var(--line);background:var(--bg)}
.pane-functions{flex:0 0 50%;min-width:18rem}
.pane-strings{flex:1 1 auto;min-width:18rem}
.pane-header{position:sticky;top:0;z-index:1;background:var(--bg);border-bottom:1px solid var(--line);padding:8px 10px}
.pane-body{display:flex;flex-direction:column;gap:8px;padding:8px 10px}
.splitter{position:relative;flex:0 0 12px;cursor:col-resize;touch-action:none}
.splitter::before{content:'';position:absolute;top:0;bottom:0;left:50%;width:1px;background:var(--line);transform:translateX(-50%)}
.splitter::after{content:'';position:absolute;top:50%;left:50%;width:3px;height:40px;border-left:1px solid var(--line);border-right:1px solid var(--line);transform:translate(-50%,-50%)}
.function-grid{display:flex;flex-wrap:wrap;gap:1px;align-content:flex-start}
.function-box{position:relative;z-index:0;width:var(--square);height:var(--square);border:1px solid var(--line);background:var(--fill);overflow:visible}
.function-box::before{content:'';position:absolute;inset:0;background:var(--heat);opacity:var(--heat-opacity,0);pointer-events:none}
.function-box::after{content:'';position:absolute;inset:-2px;border:1px solid var(--seed);opacity:0;pointer-events:none}
.function-box.is-seed::after{opacity:1}
.function-box.is-dim{opacity:.28}
.string-list{display:flex;flex-direction:column;gap:2px}
.string-row{display:flex;align-items:flex-start;gap:8px;width:100%;border:1px solid transparent;background:transparent;color:inherit;padding:3px 4px;font:inherit;text-align:left;cursor:pointer}
.string-row:hover,.string-row.is-active{border-color:var(--line)}
.string-address{color:var(--muted);white-space:nowrap;flex:0 0 auto}
.string-value{min-width:0;flex:1 1 auto;white-space:pre-wrap;word-break:break-word}
.string-tags{margin-left:auto;flex:0 0 auto;padding-left:8px;color:var(--muted);white-space:nowrap}
.tooltip{position:fixed;z-index:10;display:none;width:min(42rem,calc(100vw - 24px));max-height:calc(100vh - 24px);overflow:auto;border:1px solid var(--line);background:#fff;padding:8px;pointer-events:none;white-space:pre-wrap;box-shadow:0 2px 8px rgba(0,0,0,.08)}
.tooltip.is-visible{display:block}
h1,h2{font-size:inherit}
""".strip()

    script = """
const data=JSON.parse(document.getElementById('mapa-data').textContent);
const splitView=document.getElementById('split-view');
const functionsPane=document.getElementById('functions-pane');
const splitter=document.getElementById('splitter');
const functionBoxes=[...document.querySelectorAll('.function-box')];
const tagControls=[...document.querySelectorAll('.tag-control')];
const stringRows=[...document.querySelectorAll('.string-row')];
const directionControls=[...document.querySelectorAll('.direction-control')];
const depthControls=[...document.querySelectorAll('.depth-control')];
const neighborhoodStatus=document.getElementById('neighborhood-status');
const tooltip=document.getElementById('tooltip');
const bothByIndex=data.callersByIndex.map((callers,index)=>[...new Set([...callers,...data.calleesByIndex[index]])]);
const functionCount=data.functions.length;
let hoveredFunction=null;
let lockedFunction=null;
let hoveredTag=null;
let lockedTag=null;
let hoveredString=null;
let lockedString=null;
let directionMode='both';
let maxDepth=3;
let activePointerId=null;
let tooltipFunctionIndex=null;
let currentNeighborhood=null;
const getDecayScore=(distance)=>0.5**distance;
const hasLockedSeed=()=>lockedFunction!==null||lockedTag!==null||lockedString!==null;
const getUniqueSeedIndices=(seedIndices)=>[...new Set(seedIndices)];
const clearHoveredSeeds=()=>{
  hoveredFunction=null;
  hoveredTag=null;
  hoveredString=null;
};
const clearLockedSeeds=()=>{
  lockedFunction=null;
  lockedTag=null;
  lockedString=null;
};
const buildSeedSource=(kind,key,label,seedIndices)=>{
  const uniqueSeedIndices=getUniqueSeedIndices(seedIndices);
  if(uniqueSeedIndices.length===0){return null;}
  return {kind,key,label,seedIndices:uniqueSeedIndices};
};
const getFunctionSeedSource=(index)=>buildSeedSource('function',String(index),data.functions[index].label,[index]);
const getTagSeedSource=(tag)=>buildSeedSource('tag',tag,tag,data.tags[tag]||[]);
const getStringSeedSource=(index)=>{
  const stringData=data.strings[index];
  return buildSeedSource('string',String(index),`${stringData.value} @ ${stringData.address}`,stringData.functionIndices);
};
const getLockedSeedSource=()=>{
  if(lockedFunction!==null){return getFunctionSeedSource(lockedFunction);}
  if(lockedTag!==null){return getTagSeedSource(lockedTag);}
  if(lockedString!==null){return getStringSeedSource(lockedString);}
  return null;
};
const getHoveredSeedSource=()=>{
  if(hoveredFunction!==null){return getFunctionSeedSource(hoveredFunction);}
  if(hoveredTag!==null){return getTagSeedSource(hoveredTag);}
  if(hoveredString!==null){return getStringSeedSource(hoveredString);}
  return null;
};
const getActiveSeedSource=()=>getLockedSeedSource()??getHoveredSeedSource();
const getAdjacency=()=>{
  if(directionMode==='callers'){return data.callersByIndex;}
  if(directionMode==='callees'){return data.calleesByIndex;}
  return bothByIndex;
};
const computeNeighborhoodState=(seedIndices)=>{
  const adjacency=getAdjacency();
  const uniqueSeedIndices=getUniqueSeedIndices(seedIndices);
  const scores=new Float32Array(functionCount);
  const bestDistances=new Array(functionCount).fill(null);
  for(const seedIndex of uniqueSeedIndices){
    const distances=new Array(functionCount).fill(-1);
    const queue=[seedIndex];
    distances[seedIndex]=0;
    for(let queueIndex=0;queueIndex<queue.length;queueIndex++){
      const functionIndex=queue[queueIndex];
      const distance=distances[functionIndex];
      if(distance===maxDepth){continue;}
      for(const neighborIndex of adjacency[functionIndex]){
        if(distances[neighborIndex]!==-1){continue;}
        distances[neighborIndex]=distance+1;
        queue.push(neighborIndex);
      }
    }
    distances.forEach((distance,functionIndex)=>{
      if(distance===-1){return;}
      scores[functionIndex]+=getDecayScore(distance);
      const bestDistance=bestDistances[functionIndex];
      if(bestDistance===null||distance<bestDistance){bestDistances[functionIndex]=distance;}
    });
  }
  let maxScore=0;
  scores.forEach((score)=>{
    if(score>maxScore){maxScore=score;}
  });
  return {
    scores:Array.from(scores),
    bestDistances,
    seedIndices:uniqueSeedIndices,
    seedSet:new Set(uniqueSeedIndices),
    maxScore,
  };
};
const renderTooltipText=(index)=>{
  const summary=data.functions[index].summary;
  if(currentNeighborhood===null){return summary;}
  const lines=[`heat: ${currentNeighborhood.scores[index].toFixed(2)}`,`seed: ${currentNeighborhood.seedSet.has(index)?'yes':'no'}`];
  const distance=currentNeighborhood.bestDistances[index];
  if(distance!==null){lines.push(`distance: ${distance}`);}
  return `${lines.join('\\n')}\\n\\n${summary}`;
};
const updateTooltip=()=>{
  if(tooltipFunctionIndex===null){return;}
  tooltip.textContent=renderTooltipText(tooltipFunctionIndex);
};
const updateStatus=()=>{
  const activeSeedSource=getActiveSeedSource();
  if(activeSeedSource===null){
    neighborhoodStatus.textContent='hover or click a function, tag, or string';
    return;
  }
  const seedCount=currentNeighborhood===null?0:currentNeighborhood.seedIndices.length;
  neighborhoodStatus.textContent=`${activeSeedSource.kind} ${activeSeedSource.label} · direction ${directionMode} · depth ${maxDepth} · ${seedCount} seed${seedCount===1?'':'s'}`;
};
const updateView=()=>{
  const activeSeedSource=getActiveSeedSource();
  currentNeighborhood=activeSeedSource===null?null:computeNeighborhoodState(activeSeedSource.seedIndices);
  const hasActive=currentNeighborhood!==null;
  functionBoxes.forEach((box,index)=>{
    const score=currentNeighborhood===null?0:currentNeighborhood.scores[index];
    const heatOpacity=currentNeighborhood===null||currentNeighborhood.maxScore===0?0:score/currentNeighborhood.maxScore;
    box.style.setProperty('--heat-opacity',heatOpacity.toFixed(3));
    box.classList.toggle('is-seed',currentNeighborhood!==null&&currentNeighborhood.seedSet.has(index));
    box.classList.toggle('is-dim',hasActive&&score===0);
  });
  tagControls.forEach((control)=>{
    control.classList.toggle('is-active',activeSeedSource!==null&&activeSeedSource.kind==='tag'&&control.dataset.tag===activeSeedSource.key);
  });
  stringRows.forEach((row)=>{
    row.classList.toggle('is-active',activeSeedSource!==null&&activeSeedSource.kind==='string'&&row.dataset.stringIndex===activeSeedSource.key);
  });
  directionControls.forEach((control)=>{
    control.classList.toggle('is-active',control.dataset.direction===directionMode);
  });
  depthControls.forEach((control)=>{
    control.classList.toggle('is-active',Number(control.dataset.depth)===maxDepth);
  });
  updateStatus();
  updateTooltip();
};
const placeTooltip=(event)=>{
  const offset=12;
  let left=event.clientX+offset;
  let top=event.clientY+offset;
  const rect=tooltip.getBoundingClientRect();
  if(left+rect.width>window.innerWidth-8){left=Math.max(8,window.innerWidth-rect.width-8);}
  if(top+rect.height>window.innerHeight-8){top=Math.max(8,window.innerHeight-rect.height-8);}
  tooltip.style.left=`${left}px`;
  tooltip.style.top=`${top}px`;
};
const getPaneMinWidth=()=>parseFloat(getComputedStyle(document.documentElement).fontSize)*18;
const resizePanes=(clientX)=>{
  const rect=splitView.getBoundingClientRect();
  const splitterWidth=splitter.getBoundingClientRect().width;
  const paneMinWidth=getPaneMinWidth();
  const minLeft=rect.left+paneMinWidth;
  const maxLeft=rect.right-paneMinWidth-splitterWidth;
  if(maxLeft<=minLeft){functionsPane.style.flexBasis='50%';return;}
  const clampedLeft=Math.min(maxLeft,Math.max(minLeft,clientX));
  functionsPane.style.flexBasis=`${clampedLeft-rect.left}px`;
};
const clampPaneSize=()=>{
  const basis=parseFloat(functionsPane.style.flexBasis);
  if(Number.isFinite(basis)){resizePanes(splitView.getBoundingClientRect().left+basis);}
};
const stopResizing=(event)=>{
  if(activePointerId===null||event.pointerId!==activePointerId){return;}
  if(splitter.hasPointerCapture(event.pointerId)){splitter.releasePointerCapture(event.pointerId);}
  activePointerId=null;
  document.body.classList.remove('is-resizing');
};
functionBoxes.forEach((box,index)=>{
  box.addEventListener('mouseenter',(event)=>{
    tooltipFunctionIndex=index;
    tooltip.classList.add('is-visible');
    if(!hasLockedSeed()){hoveredFunction=index;}
    updateView();
    placeTooltip(event);
  });
  box.addEventListener('mousemove',placeTooltip);
  box.addEventListener('mouseleave',()=>{
    tooltip.classList.remove('is-visible');
    tooltipFunctionIndex=null;
    if(!hasLockedSeed()&&hoveredFunction===index){
      hoveredFunction=null;
      updateView();
    }
  });
  box.addEventListener('click',()=>{
    const functionIndex=Number(box.dataset.functionIndex);
    if(lockedFunction===functionIndex){
      lockedFunction=null;
    }else{
      clearLockedSeeds();
      lockedFunction=functionIndex;
    }
    clearHoveredSeeds();
    updateView();
  });
});
tagControls.forEach((control)=>{
  control.addEventListener('mouseenter',()=>{
    if(hasLockedSeed()){return;}
    hoveredTag=control.dataset.tag;
    updateView();
  });
  control.addEventListener('mouseleave',()=>{
    if(hasLockedSeed()||hoveredTag!==control.dataset.tag){return;}
    hoveredTag=null;
    updateView();
  });
  control.addEventListener('click',()=>{
    const tag=control.dataset.tag;
    if(lockedTag===tag){
      lockedTag=null;
    }else{
      clearLockedSeeds();
      lockedTag=tag;
    }
    clearHoveredSeeds();
    updateView();
  });
});
stringRows.forEach((row)=>{
  row.addEventListener('mouseenter',()=>{
    if(hasLockedSeed()){return;}
    hoveredString=Number(row.dataset.stringIndex);
    updateView();
  });
  row.addEventListener('mouseleave',()=>{
    if(hasLockedSeed()||hoveredString!==Number(row.dataset.stringIndex)){return;}
    hoveredString=null;
    updateView();
  });
  row.addEventListener('click',()=>{
    const stringIndex=Number(row.dataset.stringIndex);
    if(lockedString===stringIndex){
      lockedString=null;
    }else{
      clearLockedSeeds();
      lockedString=stringIndex;
    }
    clearHoveredSeeds();
    updateView();
  });
});
directionControls.forEach((control)=>{
  control.addEventListener('click',()=>{
    directionMode=control.dataset.direction;
    updateView();
  });
});
depthControls.forEach((control)=>{
  control.addEventListener('click',()=>{
    maxDepth=Number(control.dataset.depth);
    updateView();
  });
});
splitter.addEventListener('pointerdown',(event)=>{
  activePointerId=event.pointerId;
  splitter.setPointerCapture(event.pointerId);
  document.body.classList.add('is-resizing');
  resizePanes(event.clientX);
  event.preventDefault();
});
splitter.addEventListener('pointermove',(event)=>{if(activePointerId===event.pointerId){resizePanes(event.clientX);}});
splitter.addEventListener('pointerup',stopResizing);
splitter.addEventListener('pointercancel',stopResizing);
window.addEventListener('resize',clampPaneSize);
updateView();
""".strip()

    parts: list[str] = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>{escape(report.meta.name)} - mapa html map</title>",
        "<style>",
        style,
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
            '<div class="control-row">',
            '<span class="control-label">direction</span>',
            '<div class="controls" id="direction-controls">',
            '<button type="button" class="control direction-control" data-direction="callers">callers</button>',
            '<button type="button" class="control direction-control" data-direction="callees">callees</button>',
            '<button type="button" class="control direction-control is-active" data-direction="both">both</button>',
            "</div>",
            '<span class="control-label">depth</span>',
            '<div class="controls" id="depth-controls">',
            '<button type="button" class="control depth-control" data-depth="1">1</button>',
            '<button type="button" class="control depth-control" data-depth="2">2</button>',
            '<button type="button" class="control depth-control is-active" data-depth="3">3</button>',
            '<button type="button" class="control depth-control" data-depth="4">4</button>',
            "</div>",
            "</div>",
            '<div class="meta" id="neighborhood-status"></div>',
            '<div class="legend">fill = neighborhood heat · outline = seed · dim = outside neighborhood</div>',
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
            script,
            "</script>",
            "</body>",
            "</html>",
        ]
    )

    return "\n".join(parts)
