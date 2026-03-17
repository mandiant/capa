> read problem-transcript.md and digest it, summarize it, restructure it and explain it.
>
> ok. now ultrathink. consider the problem deeply. try to give some insights, some novel perspective, ideas for techniques and algorithms. what strikes you?

I've been sitting with this for a while. Here's what strikes me, organized from the structural observations that feel most fundamental down to concrete algorithmic ideas.

------

## The Deep Structure: A Graph Pinned to a Line

The most mathematically distinctive thing about this problem is that you have a *graph* (the call graph, the data xref graph) whose nodes are *pinned to a one-dimensional manifold* (the address space). This is a very specific structure that most generic graph algorithms ignore entirely. It means you're not just doing community detection — you're doing community detection where the communities are *intervals*. That's a massive constraint that dramatically shrinks the search space.

Think about it: if you have 10,000 functions, the number of arbitrary partitions is astronomically large. But the number of ways to partition 10,000 linearly-ordered nodes into *contiguous groups* is only on the order of 2^10,000 in the worst case, and if you're looking for, say, 20 boundaries, it's just C(10000, 20) — large, but tractable with dynamic programming. The contiguity assumption turns a combinatorially explosive problem into something closer to 1D segmentation, which is a much better-understood and more tractable class of problems.

## The Call Edge Length Distribution — A Fingerprint of Structure

Here's an idea I find really compelling. For every edge in the call graph, compute the *address distance* between caller and callee: `|addr(A) - addr(B)|`. Now plot the histogram of these edge lengths across the whole binary.

I'd expect this histogram to be multimodal. There should be a peak near zero representing intra-compilation-unit calls (functions calling their neighbors). There should be a broader hump at medium range representing intra-library cross-CU calls. And there should be long-range outliers representing cross-boundary calls — where user code calls into a library at a distant address.

The valleys between these modes are telling you the *characteristic scales* of the hierarchy. The first valley gives you the typical size of a compilation unit. The second gives you the typical size of a library. This is essentially a multi-scale analysis of the binary's structure, and you get it almost for free before running any clustering algorithm. You could use those characteristic distances as thresholds for later steps.

## Min-Cut / Max-Flow for Boundary Detection

The transcript describes a "tension" along paths between known first-party anchors (like `main`) and known library anchors (like FLIRT-matched or string-anchored functions). This maps almost perfectly to a **minimum cut problem**.

Set it up like this: create a super-source *S* connected to all known first-party nodes, and a super-sink *T* connected to all known library nodes. The edges in the call graph get capacities. What should the capacity be? This is where you encode your priors — you could weight by *inverse address distance* (so cutting a long-range edge is cheap, cutting a short-range edge between neighbors is expensive), or by the number of shared data references, or both. Then the min-cut between S and T partitions the graph into first-party and third-party, and the *cut edges themselves are literally the API boundary* — the places where user code transitions into library code.

This is elegant because it naturally handles ambiguity. You don't have to hand-define a propagation rule; the flow algorithm figures out where the cheapest place to draw the line is. And you can add new anchors (from FLIRT, strings, human input) simply by connecting them to S or T, and the cut re-adjusts.

## The Genome Annotation Analogy

This problem is strikingly similar to **genome annotation** in bioinformatics. You have a long linear sequence (the binary). It contains functional regions (genes = functions). These regions cluster into operons and gene families (compilation units, libraries). You have some known markers (homolog matches ≈ FLIRT signatures). You want to segment the sequence into regions of different character, exploiting the fact that related elements are co-located.

The classic tool for this is the **Hidden Markov Model**. Imagine an HMM where the hidden states represent "this function belongs to first-party code," "this function belongs to library A, CU 1," etc. The observations at each state are the features of that function — its string references, its call graph characteristics, its instruction patterns. The transition probabilities encode the contiguity assumption: staying in the same CU is high probability, transitioning between CUs within a library is medium, jumping between libraries is low.

You'd train this in a semi-supervised way, anchoring some states with your ground truth, and letting Viterbi or forward-backward propagate through the rest. The HMM framework is natural here because the binary *is* a sequence, and the Markov property (what matters is what group you're currently in, not the full history) matches the linker's behavior well.

## Personalized PageRank as a Soft Classification

Here's a technique that handles the graph propagation cleanly. Run **personalized PageRank** (PPR) seeded from each anchor set. One PPR vector seeded from `main` gives you a "reachability-from-first-party" score for every node. Another seeded from known zlib functions gives a "zlib affinity" score. A third from OpenSSL anchors gives an "OpenSSL affinity" score.

Each function is then softly classified by which PPR vector dominates at that node. The beauty is that PPR naturally decays with graph distance and respects the connectivity structure — a tightly-knit library will "trap" the random walk, giving high PPR scores internally and low scores outside. The boundary between two regions is where the competing PPR scores cross over.

You could even visualize this as a heat map over the address space, and the boundaries would pop out visually.

## Exploiting the Bipartite Structure: Code ↔ Data

The transcript mentions that data locality mirrors code locality, but I think this signal is underexploited if you treat it as a separate, independent confirmation channel. Consider the *bipartite graph* between functions and the data items they reference. Two functions that reference overlapping or nearby data are likely from the same compilation unit. This gives you a similarity measure between functions that's *completely independent* of the call graph.

You could build a function-to-function similarity matrix where similarity = how much their referenced data overlaps or how close their referenced data is in the data section. Then cluster on this matrix. The resulting clusters should correspond to compilation units, and they give you a second opinion that you can reconcile with the call-graph-derived clusters.

When both signals agree, you have high confidence. Where they disagree, something interesting is happening — maybe a utility function shared across CUs, or a data section that got reordered.

## Directed Graph Asymmetry as a Library Detector

Here's a subtlety the transcript alludes to but doesn't fully develop. Call graphs are *directed*, and the directionality matters. Library code has a specific shape: it gets **called from far away** (user code invokes the library's public API) but **calls to nearby functions** (internal library routines). So a library entry point has high *in-degree from distant addresses*but low *out-degree to distant addresses*.

You could compute, for each function, two metrics: the average address distance of its callers, and the average address distance of its callees. Plot every function on this 2D plane. I'd expect clusters to emerge — first-party code has short-range callers and a mix of callees (some local, some long-range calls into libraries), while library internals have short-range everything. Library *entry points* are the distinctive ones: long-range callers, short-range callees. They're the "necks" between the communities.

## The Bisection Oracle Strategy

The "git bisect" idea from the transcript is really interesting and I think it deserves formal treatment. If you have an expensive oracle (heavy analysis, LLM query, human analyst) and you want to minimize queries, this is an **active learning** problem.

Concretely: you have a sequence of functions ordered by address, and you know that somewhere in this sequence there's a boundary between first-party and library code. You believe the sequence is monotonic (once you cross from first-party to library, you don't come back — at least within a region). Binary search finds the boundary in O(log n) queries. But real binaries might have multiple interleaved regions, so you'd need a slightly more sophisticated approach — maybe something like the **multi-armed bandit** formulation, where each candidate boundary location has an uncertainty estimate, and you query the point that maximally reduces global uncertainty.

## Strongly Connected Components as Ground Truth CU Detectors

One more concrete trick: compute the **strongly connected components** of the call graph. Mutual recursion (A calls B, B calls A) almost always happens within a single compilation unit. So SCCs give you "for free" sets of functions that definitely belong together. These become seeds for clustering — merge each SCC into a single super-node, then run your boundary detection on the reduced graph.

------

## Synthesis

If I were designing the pipeline, I'd layer these techniques:

Start with **cheap deterministic anchors** — FLIRT matches, string attribution, `main` identification. Then use the **edge-length histogram** to estimate the characteristic scales. Run **SCC detection** to collapse definite-same-CU functions. Build edge weights from address proximity and shared data references, then use **min-cut** from known-first-party to known-library to find the primary boundary. Within each side, use **agglomerative clustering** on the address axis, breaking only at points where the call graph edge density drops off, to find compilation unit boundaries. Use **personalized PageRank** from each library's anchors for soft assignment. Finally, reconcile against the **data xref bipartite clustering** as independent validation.

The result would be a hierarchical segmentation of the address space with confidence scores, and the boundaries would be exactly the API transition points that a reverse engineer cares about.



---

These are good, and the interesting thing is where they overlap with what I already proposed — and more importantly, where the *gaps between them* reveal something deeper. Let me think through what these trigger.

------

> here are some additional ideas. do they cause you to have any new insights or ideas?
>
> To transition MAPA from a good heuristic tool to a cutting-edge analytical engine, here are four algorithms that fit perfectly into their architecture: Algorithm 1: Spatial-Graph Label Propagation (Solving the "Tension") Instead of manually traversing graphs, use Label Propagation.
>
> 1. Build an adjacency matrix of the functions.
> 2. Weight the edges by both call frequency AND physical memory proximity. (e.g., Function A and B are strongly linked if A calls B and they are 100 bytes apart).
> 3. Lock the "Anchor" nodes (Ground Truth).
> 4. Run the propagation algorithm. It will mathematically resolve the "tension" the speaker mentioned, assigning a probability score to every single function (e.g., "Function 0x40100 is 88% likely to be zlib"). Algorithm 2: Spectral Clustering for "Compilation Units" The speaker wants to identify individual compilation units (source files). Because linkers lay out source files contiguously, compilation units form ultra-dense "cliques" in the graph.
>
> - Use Spectral Graph Partitioning. By calculating the Laplacian of the call graph, the algorithm will naturally shatter the binary into discrete chunks.
> - Because compilation units are sequential in memory, you can penalize the clustering algorithm for grouping functions that are physically far apart. The output will be distinct, colored blocks perfectly mapping to the original .c or .cpp files. Algorithm 3: Minimum Cut / Maximum Flow for API Boundaries To find the exact boundary between user code and library code, treat the graph like a pipe network carrying water from main to the library strings.
> - Run a Min-Cut/Max-Flow algorithm. The algorithm will identify the "bottleneck" edges where water struggles to pass from the malware to the library.
> - Those bottlenecks are, almost by definition, the public API functions of the statically linked library.



## The Three Algorithms Are Solving Three Different Sub-Problems

The most important realization is that these three aren't competing approaches — they're a **layered pipeline** attacking different levels of the hierarchy. Min-cut finds the macro boundary (first-party vs. library). Spectral clustering finds the meso-structure (compilation units). Label propagation assigns soft identities (which library, what confidence). That ordering matters, and each stage's output feeds the next.

But there's something missing from this pipeline: none of them address **how to discover the right number of groups**. Min-cut gives you a bisection, but a real binary might have first-party code plus six libraries. Spectral clustering needs you to pick *k*. Label propagation needs seed labels. So the first real question is: **how many libraries are we even looking for?**

## The Eigengap Tells You How Many Libraries Exist

This is where the spectral approach becomes more powerful than the proposal suggests. Don't just use spectral clustering to *partition* — first use the **eigenvalue spectrum of the graph Laplacian** to *discover* the structure. Specifically, compute the first, say, 50 eigenvalues of the address-weighted call graph Laplacian and look for the **eigengap** — the largest jump between consecutive eigenvalues. If the first three eigenvalues are near zero and then the fourth jumps up, that's telling you the graph has roughly three natural communities. You've learned the number of libraries (plus first-party code) before doing any clustering at all.

Even better: the **eigenvectors** themselves, when plotted against function address, should look like step functions. Within a compilation unit, all functions have similar eigenvector values (because they're tightly coupled). At a boundary, the values jump. So you can literally do **change-point detection on the Fiedler vector** (the eigenvector corresponding to the second-smallest eigenvalue) plotted over the address axis, and the change points are your compilation unit boundaries. This fuses the spectral and spatial approaches in a way that's more principled than penalizing distance in the clustering objective.

## The Weighting Scheme Deserves More Thought

Algorithm 1 proposes weighting edges by call frequency AND memory proximity. This sounds right but the *combination function* matters enormously. Additive weighting (`w = α·calls + β·proximity`) treats them as interchangeable signals. Multiplicative weighting (`w = calls · f(proximity)`) treats proximity as a **prior** that modulates graph evidence. I think the multiplicative form is more correct.

Here's why: a call edge between two functions 50 bytes apart is *qualitatively different* from a call edge between two functions 500KB apart. The first is almost certainly intra-CU. The second is almost certainly cross-boundary. The call exists in both cases, but its *meaning* changes based on distance. A multiplicative weight captures this — a long-range call gets a small weight, so cutting it is cheap (it's probably a cross-boundary call), while cutting a short-range call is expensive.

Concretely, something like `w(e) = calls(e) · exp(-distance(e) / λ)` where λ is the characteristic CU size (which you estimated from the edge-length histogram I described earlier). This exponential decay naturally encodes "nearby calls bind tightly, distant calls bind weakly."

## A Critique of Min-Cut That Leads Somewhere Interesting

The min-cut formulation as described has a subtle problem: it's **binary**. It partitions into first-party and library. But what if there are three libraries? You'd need to run it multiple times, or use multi-terminal cut, which gets expensive.

But here's what the min-cut framing *does* give you that's uniquely valuable: the **cut edges are the API boundary**, and the **capacity of the cut is a confidence measure**. A large min-cut value means the boundary is well-defined (lots of edges had to be severed). A small min-cut means the separation is tenuous — maybe you've drawn the line in the wrong place, or maybe the "library" is actually tightly integrated with user code.

This leads to a practical idea: **iterate**. Run min-cut to get a first-party/library partition. Then *within the library side*, run min-cut again between the two most distant anchor sets (say, zlib anchors vs. OpenSSL anchors). This recursive bisection via min-cut naturally produces the hierarchy. And at each level, the cut capacity tells you how confident you should be.

## A New Idea These Three Together Trigger: Diffusion Distance as a Universal Metric

All three algorithms are really measuring the same underlying thing from different angles: **how easily does information flow between two nodes?** Label propagation is a diffusion process. Spectral clustering uses the eigenvectors of the diffusion operator. Min-cut measures the bottleneck in flow.

This suggests a unifying abstraction: compute the **diffusion distance** between every pair of functions. Diffusion distance is the L2 distance between the rows of the matrix `exp(-t·L)` where L is the graph Laplacian and t is a time parameter. At small t, only very close (tightly connected, nearby) functions are similar. At large t, entire libraries blur into single points.

The beauty is that **different values of t reveal different levels of the hierarchy**. Small t resolves compilation units. Medium t resolves libraries. Large t resolves the first-party/library split. You get the entire hierarchical segmentation from a single mathematical object just by tuning a parameter.

You could visualize this as a dendrogram: at what "diffusion time" do two functions merge into the same cluster? Functions in the same CU merge almost immediately. Functions in the same library merge at medium time. Everything merges eventually. The dendrogram *is* the hierarchical classification you're after.

## One Final Practical Insight: Robustness to Bad Disassembly

All of these techniques assume the call graph is accurate, but in real binaries — especially malware — disassembly is imperfect. Indirect calls get missed. Tail calls look like jumps rather than calls. Obfuscated code deliberately breaks analysis.

This is where the **spatial signal acts as a safety net**. Even when the graph is incomplete or noisy, the address layout is always there and always reliable. If your spectral clustering says two functions belong in different groups but they're 20 bytes apart with no other functions between them, the spatial evidence should override. The address axis is your highest-confidence signal; the graph is the informative but noisy supplement. Any algorithm you build should be designed to degrade gracefully — if the graph were *completely* absent, you should still be able to do a passable job purely on address-range heuristics and data xref locality. The graph makes it better, but the 1D structure is the backbone.

---

> here are some further considerations. how should we integrate them into our list of strategies?
>
> 1. Features that seem underexploited.
>
> - 23a. Shared constant pools and tables.
> - 23b. Exception/unwind metadata neighborhoods.
> - 23c. Import-family fingerprints.
> - 23d. Repeated alignment and gap patterns between code blocks.
> - 23e. Data-section locality matching code-section locality.
> - 23f. Ego-network shape: not just who a function calls, but what its 1-hop and 2-hop neighborhood looks like.
> - 23g. Call-direction asymmetry across a candidate boundary.
>
> 1. A specific novel tactic: score gaps, not just nodes.
>
> - 24a. For each gap between adjacent functions in address order, compute “boundary likelihood.”
> - 24b. Features could include:
>   - sudden change in seed evidence
>   - reduced internal xrefs across the gap
>   - padding/alignment pattern
>   - change in referenced data neighborhood
>   - change in import/API usage style
>   - change in graph embedding neighborhood
> - 24c. Then solve for a sparse set of boundaries.
> - 24d. This is more direct than asking “what label is each function?”
>
> 1. Another promising tactic: recover “data islands” first.
>
> - 25a. Cluster strings/tables/rodata/data by address locality and xref neighborhoods.
> - 25b. Label those islands with higher confidence than code.
> - 25c. Then attach functions to the islands they reference.
> - 25d. Libraries often expose themselves through data long before their code is obvious.
>
> 1. A third tactic: active refinement near high-entropy frontiers.
>
> - 26a. Most of the binary may be easy.
> - 26b. The cost is concentrated near a few uncertain boundaries.
> - 26c. So only there should MAPA use expensive methods:
>   - deeper semantic analysis
>   - more complex embeddings
>   - decompiler-derived features
>   - analyst interaction
> - 26d. This is much better than spending equal effort on every function.

These four ideas aren't just additions to the list — they restructure how I think the whole pipeline should work. Let me explain why.

## The Paradigm Shift: Score Boundaries, Not Functions

Item 24 is the single most important idea in this entire conversation so far, and I think it should become the **primary framing** of the problem rather than a tactic alongside others.

Every algorithm we've discussed — label propagation, spectral clustering, min-cut, PPR, HMMs — has been asking "what label does each function get?" But that's the indirect question. The direct question is "where are the seams?" And those seams live *between* functions, in the gaps. This reframing matters practically because the number of gaps (N-1 for N functions) is fixed, the features per gap are rich and computable, and the output you actually want — a segmentation — is literally a sparse subset of those gaps marked as boundaries.

This turns the whole problem into **supervised or semi-supervised boundary classification on a 1D sequence of gaps**, which is vastly simpler and more tractable than graph community detection. You compute a feature vector for each gap, you have some gaps where you know a boundary exists (between a FLIRT-matched library function and an adjacent non-library function, for instance), and you train a classifier. Or you don't even need training — you define a scoring function and then solve for the *sparsest* set of boundaries that explains your evidence, which is essentially LASSO or L1-penalized segmentation.

The gap features listed in 24b are excellent, and I'd add a few more that fall out of the earlier discussion: the diffusion distance between the functions flanking the gap, the min-cut capacity if you sever the graph at that point, and the eigenvector discontinuity at that gap in the Fiedler vector. Every algorithm we previously discussed becomes a **feature generator for the gap scorer** rather than a standalone solution. That's the architectural insight — the boundary scorer is the spine, and everything else feeds into it.

## Data Islands as the Foundation Layer

Item 25 is the second most important idea, and it reorders the pipeline in a way I didn't previously consider. The argument is subtle and correct: data is *more reliably clusterable than code* for several reasons. Strings are human-readable and often uniquely attributable to a library. Data items don't have the ambiguity of indirect calls. The data section layout reflects compilation unit structure just as faithfully as the code section, but with less noise. And critically, data doesn't get obfuscated nearly as often as code does in malware — the strings still need to be there at runtime.

So the pipeline should be: cluster the data section first into "islands" using address locality and cross-reference structure. Label those islands using string content, constant patterns, and any other attributable features. Then project those labels back onto functions via data references. A function that references three strings in the "zlib island" is almost certainly zlib code, even if you've never seen its bytes before and FLIRT doesn't match it.

This is powerful because it provides anchors that are **denser and more confident** than what you get from FLIRT or code-side analysis alone. It also means the data-island clustering becomes the *first* stage of the pipeline, before any code-side graph analysis. You start from data, anchor the code, then refine.

## The Underexploited Features Suggest a Richer Feature Space for Gaps

Items 23a through 23g aren't just a wishlist — they fill specific blind spots in the gap scoring framework:

**23a (shared constant pools/tables)** and **23e (data-section locality)** feed directly into the data-island strategy. But they also provide a gap feature: if the functions on either side of a gap reference data from the *same* data island, the gap is unlikely to be a boundary. If they reference data from *different* islands, it probably is.

**23b (exception/unwind metadata)** is a particularly clever signal I hadn't considered. Exception handling tables are generated per-compilation-unit by most compilers, and the unwinder metadata groups functions together in a way that directly reflects CU boundaries. This is almost ground truth when it's present — you should parse `.pdata`/`.xdata` (on Windows) or `.eh_frame` (on Linux) and treat co-membership in the same unwind group as a hard constraint. Functions sharing an unwind info record are in the same CU, period.

**23c (import-family fingerprints)** is interesting because it captures *style*. First-party code that does file I/O will call a different set of APIs than zlib's compression internals. You're not just looking at individual API calls — you're looking at the *distribution* of API families a function touches. Two functions that both use memory allocation + string manipulation + crypto APIs probably belong to the same logical unit (maybe an OpenSSL subsystem), while a function that only touches file I/O is probably a different module. This becomes a gap feature: does the API usage style change across this gap?

**23d (alignment and padding patterns)** is a beautiful low-level signal. Compilers emit characteristic alignment between functions (16-byte alignment, `int3` padding on MSVC, `nop` sleds on GCC). But *linkers* insert different padding between compilation units — often larger gaps or different padding bytes. So the gap's physical characteristics (how many bytes of padding, what the padding looks like) are direct evidence of whether it's an intra-CU gap or an inter-CU gap. This is a nearly free feature that requires no graph analysis at all.

**23f (ego-network shape)** is where things get really interesting algorithmically. Two functions might both have degree 5 in the call graph, but one's ego network is a tree (it calls 5 leaf functions that call nothing else — probably a dispatcher or API facade) while the other's ego network is a dense clique (its 5 callees all call each other — probably deep library internals). The *shape* of the local neighborhood, not just its size, is a fingerprint of where you are in the program's structure. You could compute small graph motif counts or local clustering coefficients and use those as features.

**23g (call-direction asymmetry)** completes the picture for boundary detection specifically. At a real API boundary, you expect calls going *into* the library (from the user-code side) but not calls going *out* of the library back into user code (libraries don't call their callers). So at a candidate boundary gap, you count directed edges crossing it in each direction. A strong asymmetry — many calls going deeper, few or none coming back — is a strong boundary signal. A gap where calls flow freely in both directions is probably internal to a single module.

## Active Refinement as the Final Stage, Not a Separate Strategy

Item 26 should be understood as the **execution strategy** for the whole pipeline, not a separate algorithm. The core insight is that uncertainty is spatially concentrated. After running the cheap, fast stages (data island clustering, gap feature computation, label propagation from anchors), most of the binary is probably classified with high confidence. What remains is a handful of ambiguous frontier zones — maybe 5-10% of the address space where two competing labels are close in score.

This is where you focus your expensive techniques: run the decompiler only on the ambiguous functions. Compute embeddings only for the frontier. Query the analyst only about the uncertain gaps. And do it in the "bisect" order — query the gap in the middle of the largest remaining uncertain region first, because its answer splits the ambiguity in half.

This means the pipeline architecture should explicitly support a **confidence map** over the address space. Every stage produces not just labels but uncertainty estimates. The uncertainty map guides where to spend further effort. And there's a natural stopping criterion: stop when the maximum remaining uncertainty drops below a threshold, or when the analyst says "good enough."

## The Revised Pipeline

Integrating everything, here's how I'd now structure it:

**Stage 0 — Feature extraction.** Parse the binary. Extract functions, call graph, data xrefs, strings, exception metadata, alignment patterns, import calls. Cheap and mechanical.

**Stage 1 — Data island clustering.** Cluster the data section by address locality and xref structure. Label islands using string content and constant pool attribution. This gives you the densest, most confident set of anchors.

**Stage 2 — Anchor projection.** Project data-island labels onto functions via xrefs. Combine with FLIRT matches and known entry points (`main`, etc.). Every function now has either a confident label, a tentative label, or no label.

**Stage 3 — Gap scoring.** For every inter-function gap, compute the full feature vector: padding pattern, data-island change, API style change, call-graph edge density across the gap, call-direction asymmetry, ego-network similarity of flanking functions, exception metadata boundary, eigenvector discontinuity. Score each gap's boundary likelihood.

**Stage 4 — Segmentation.** Solve for the sparse set of boundaries that best explains the gap scores and the anchor constraints. This could be L1-penalized changepoint detection, or an HMM where the gap scores inform transition probabilities.

**Stage 5 — Label assignment.** Within each segment, assign a library/CU label using the anchors, propagated labels, and graph community structure. This is where label propagation or spectral methods work *within* the already-established boundaries rather than trying to find them.

**Stage 6 — Active refinement.** Identify the highest-uncertainty boundaries. Apply expensive techniques — decompilation, semantic analysis, analyst queries — specifically at those points. Update the segmentation. Repeat until confidence is sufficient.

The key design principle is that boundary detection (stages 3-4) and label assignment (stage 5) are **decoupled**. You find where the seams are first, then figure out what's on each side. And the most reliable signals (data, metadata, physical layout) come first, with the noisier signals (graph topology, semantic analysis) used for refinement rather than discovery.
