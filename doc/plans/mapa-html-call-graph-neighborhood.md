# mapa plan: html call-graph neighborhood view

This plan explores a larger-neighborhood view for the HTML map. Today the page shows only direct relationships. A tag marks functions that reference strings with that tag, and a string marks functions that reference that exact string. The proposed experiment is to push that signal backward through the call graph so the page can show the code region around those direct hits.

The real question is whether the larger neighborhood stays localized enough to be useful. If a `#zlib` string grows into one compact region when we include one, two, or three caller hops, that supports the idea that tagged strings can anchor a broader library region. If the overlay quickly spreads into generic wrappers and dispatchers, the direct-hit view is probably carrying most of the useful signal already.

## Current behavior

The collector already has most of the data needed for this experiment. `mapa/collector.py` resolves thunk targets, builds `resolved_callers` and `resolved_callees`, and stores those relationships on each `MapaFunction` as `callers` and `calls`. The report model therefore already contains a usable reverse call graph.

The HTML renderer does not use that graph today. `mapa/html_renderer.py` emits only the function tooltip text, a tag-to-function index, and string rows with their direct function indices. The browser script then applies three binary states: tag border on, string fill on, or dim. There is no traversal, no score, and no way to distinguish direct evidence from nearby code.

One detail matters for later weighting. `_collect_tag_entries()` collapses each tag to a set of functions. That is enough for the current binary view, but it drops multiplicity. If one function references several `#zlib` strings, the current page still treats that as one direct hit. That simplification is acceptable for a first neighborhood experiment, but it becomes relevant if we later want repeated string evidence to count more strongly.

## Proposed model

The first experiment should use caller-depth propagation only. For a selected tag or string, define the directly matching functions as depth 0. Then walk backward through callers. Depth 1 is the callers of direct-match functions, depth 2 is the callers of depth-1 functions, and so on. A bounded depth of 0 to 3, or at most 4, is enough for the experiment.

The overlay should weaken with distance. Direct matches stay strongest. Indirect matches fade with depth. A simple additive model is enough. Each direct-match function contributes a seed weight of 1.0. A caller at depth `d` receives `seed_weight * decay(d)`. If several matching paths reach the same function, add the contributions together. That gives the effect we want. A function that sits above several tagged descendants should stand out more than a function that reaches only one.

Two decay families are worth trying. Harmonic decay follows the original intuition of 1.0, 1/2, 1/3, 1/4. Geometric decay uses 1.0, 1/2, 1/4, 1/8. Harmonic keeps more mass at larger depths. Geometric is more conservative and is less likely to smear across the whole map through generic caller chains. The page should probably expose both and default to geometric.

For the first pass, the seed should be per direct-match function rather than per direct-match string. That keeps the experiment focused on graph expansion instead of mixing graph expansion with direct evidence density. If the idea looks useful, then a second pass can try per-string seeds or rarity-weighted seeds.

## What the page should show

The current page already has a useful split between tag selection and string selection. Tag selection uses the border and string selection uses the fill. That can stay. The propagation engine can compute two separate score arrays, one for the border channel and one for the fill channel. If both a tag and a string are active, both overlays remain visible.

The main challenge is interpretation. A single cumulative heat map can look compelling while hiding the reason a function is lit up. The user should be able to tell the difference between a direct match, a one-hop caller, and a function that receives several weak contributions through different paths. For that reason, the page should support both cumulative and exact-hop views. In cumulative mode, the page shows the total score up to the chosen depth. In exact-hop mode, the page shows only depth 0, or only depth 1, or only depth 2. If there is room, small multiples would be even better. Four aligned copies of the same function grid for depths 0 through 3 would make locality much easier to judge.

Direct matches should remain visually distinct from indirect ones. A direct seed should not disappear into the same faint channel as a weak propagated score. Tooltips should also report the exact score for the active overlay. Otherwise the view will be hard to debug.

## Recommended first implementation

The narrow version of this feature can stay almost entirely inside `mapa/html_renderer.py`. The collector already records the caller relationships needed for bounded backward traversal.

The renderer should emit one more structure in its inline JSON: `callersByIndex`, a reverse adjacency list keyed by function index. It can keep the existing direct seed data for tags and strings. The browser script can then compute scores on demand for the active selection. The data volume is small enough that this should stay cheap on typical samples.

The computation can stay simple. Initialize the direct-match functions as the depth-0 frontier. For each depth from 1 to `maxDepth`, push the previous frontier to its callers, multiply the step by the chosen decay factor, and add the contributions into a total score array. This counts bounded walks rather than strictly simple paths. With shallow depths, that is a reasonable approximation.

The first UI pass only needs a few controls: maximum caller depth, decay family, and view mode. The existing function grid and string list can remain in place.

A practical first cut would keep these defaults:

- caller-only propagation
- default depth of 2
- geometric decay
- additive scoring
- cumulative view, with exact-hop available as a switch

## Rendering considerations

The current 10-pixel square is large enough for a binary on/off signal, but it may be too small for subtle border intensity changes. Border alpha alone may be hard to read. A better approach is to keep direct tag hits as a solid border and render propagated tag scores with either a stronger border color ramp or a small glow. For strings, direct matches can keep the current solid fill while propagated scores use a fill alpha ramp. The exact styling can stay simple, but direct and indirect states should be separable at a glance.

The page should also keep dimming non-matches when any overlay is active. Otherwise weak propagated scores will be visually lost in large samples.

## Risks

The main risk is graph bleed. Generic wrappers, initialization code, dispatchers, shared error handlers, and utility helpers often sit one or two caller hops above many unrelated regions. Those functions can make the map look more connected than the underlying library region really is.

Cycles are another risk. Recursive or mutually recursive groups can accumulate score in ways that are mathematically consistent under a bounded-walk model but visually misleading. Strongly connected component collapsing is a possible future refinement, but it should not be part of the first pass.

These risks argue for conservative defaults. Caller-only propagation is easier to reason about than a bidirectional neighborhood. Depth should stay shallow. Geometric decay is a safer default than harmonic. Exact-hop inspection should be available so the user can see whether the first one or two shells are still localized.

## Variations worth testing

If the first pass looks promising, there are several obvious follow-ons.

One variation is seed definition. Compare per-function seeds, per-string seeds, and rarity-weighted seeds. The last option is appealing because `StringTagMatch` already preserves `global_count`, and rare strings are usually more diagnostic than common ones.

Another variation is degree normalization. Raw additive scoring favors functions that sit above many matching descendants. That is partly what we want, but it also rewards generic coordinator functions. A normalized variant could divide contributions by a degree term and ask a different question: how concentrated is the evidence in this function's neighborhood.

A thresholded view is also worth trying. Instead of showing a continuous score ramp, let the user set a minimum score and mark only functions above that threshold. That could make contiguous regions easier to spot.

A comparison mode would be useful as well. Showing direct-only and propagated views side by side would make it easy to see whether the larger neighborhood adds a coherent region or just noise.

## How to evaluate the idea

The function grid is address-ordered, so this experiment is really about locality in address space. The first thing to look for is whether shallow propagation expands a direct-hit cluster into a still-coherent region. Good test cases are binaries where we already expect a compact static-library region, such as zlib, OpenSSL, or sqlite3.

It would also help to add a few quantitative summaries. The page could report the smallest contiguous address span containing most of the score mass, how many separate spans remain above a threshold, and how those numbers change as depth increases. That would make the result less subjective.

The concept is worth implementing as an experiment. The hard data is already present in the report model, and a conservative first pass can stay mostly inside the HTML renderer. If shallow caller propagation still yields compact regions for known libraries, then richer weighting models are worth exploring. If it smears immediately, that is still a useful result and tells us that the direct-hit view is already close to the limit of the available signal.
