/**
 * Coverage Tracking Module
 *
 * Implements edge coverage tracking inspired by AFL's coverage-guided
 * fuzzing (Böhme et al., "Coverage-based Greybox Fuzzing as Markov Chain",
 * CCS 2016). Uses a bitmap to track execution edges and bucketed hit counts
 * for efficient coverage deduplication.
 *
 * References:
 * - AFL: american fuzzy lop (Zalewski, 2014)
 * - AFL++: Combined instrumentation (Fioraldi et al., USENIX WOOT 2020)
 * - LibFuzzer: coverage-guided evolutionary fuzzer (LLVM Project)
 */

const BITMAP_SIZE = 65536; // 2^16 - standard AFL bitmap size

// AFL-style hit count bucketing: reduces noise from exact counts
// Maps raw hit counts to logarithmic buckets
const HIT_COUNT_BUCKETS = [1, 2, 3, 4, 8, 16, 32, 128];

function bucketize(count) {
  for (let i = HIT_COUNT_BUCKETS.length - 1; i >= 0; i--) {
    if (count >= HIT_COUNT_BUCKETS[i]) return HIT_COUNT_BUCKETS[i];
  }
  return 0;
}

export class CoverageTracker {
  constructor() {
    // Edge coverage bitmap (AFL-style shared memory bitmap)
    this.globalBitmap = new Uint8Array(BITMAP_SIZE);
    // Per-input coverage for determining novelty
    this.inputCoverageHistory = [];
    // Total edges discovered over time (for saturation analysis)
    this.edgeDiscoveryTimeline = [];
    this.totalEdgesDiscovered = 0;
    this.totalInputsProcessed = 0;
  }

  /**
   * Create a fresh bitmap for a single execution run.
   */
  createLocalBitmap() {
    return new Uint8Array(BITMAP_SIZE);
  }

  /**
   * Record an edge hit in a local bitmap.
   * Edge ID is computed as hash(prevLocation XOR currentLocation) per AFL.
   *
   * @param {Uint8Array} localBitmap - per-execution bitmap
   * @param {number} prevLocation - previous basic block ID
   * @param {number} currentLocation - current basic block ID
   */
  recordEdge(localBitmap, prevLocation, currentLocation) {
    const edgeId = (prevLocation ^ currentLocation) % BITMAP_SIZE;
    localBitmap[edgeId] = Math.min(255, localBitmap[edgeId] + 1);
  }

  /**
   * Simulate edge coverage from trace data (property accesses, function
   * calls, prototype changes). Each event type gets a unique location hash.
   *
   * @param {object} trace - execution trace from instrumentation
   * @returns {Uint8Array} local bitmap for this execution
   */
  computeCoverageFromTrace(trace) {
    const localBitmap = this.createLocalBitmap();
    let prevLocation = 0;

    // Property accesses represent control-flow edges through object lookups
    for (const access of (trace.propertyAccesses || [])) {
      const loc = this.hashLocation('prop', access.property, access.object);
      this.recordEdge(localBitmap, prevLocation, loc);
      prevLocation = loc >> 1; // AFL right-shift to avoid collisions
    }

    // Function calls represent call-graph edges
    for (const call of (trace.functionCalls || [])) {
      const loc = this.hashLocation('call', call.function, '');
      this.recordEdge(localBitmap, prevLocation, loc);
      prevLocation = loc >> 1;
    }

    // Prototype changes represent critical security-relevant edges
    for (const change of (trace.prototypeChanges || [])) {
      const loc = this.hashLocation('proto', change.property || change.type, change.target);
      this.recordEdge(localBitmap, prevLocation, loc);
      prevLocation = loc >> 1;
    }

    // Sink accesses are the ultimate targets
    for (const sink of (trace.sinkAccesses || [])) {
      const loc = this.hashLocation('sink', sink.sink, '');
      this.recordEdge(localBitmap, prevLocation, loc);
      prevLocation = loc >> 1;
    }

    return localBitmap;
  }

  /**
   * Simple string hash for generating location IDs.
   * Uses DJB2 hash (Bernstein, 1991) - fast and sufficient for coverage.
   */
  hashLocation(type, name, context) {
    const str = `${type}:${name}:${context}`;
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) + hash + str.charCodeAt(i)) & 0xFFFF;
    }
    return hash;
  }

  /**
   * Merge a local bitmap into the global bitmap and determine if
   * new coverage was found. Uses AFL's bucketed hit count comparison.
   *
   * @param {Uint8Array} localBitmap
   * @returns {object} { isNovel, newEdges, totalEdges }
   */
  mergeAndCheckNovelty(localBitmap) {
    let newEdges = 0;
    let totalEdges = 0;

    for (let i = 0; i < BITMAP_SIZE; i++) {
      if (localBitmap[i] === 0) continue;
      totalEdges++;

      const localBucket = bucketize(localBitmap[i]);
      const globalBucket = bucketize(this.globalBitmap[i]);

      // New coverage: either new edge or new hit count bucket
      if (localBucket > globalBucket) {
        newEdges++;
        this.globalBitmap[i] = Math.max(this.globalBitmap[i], localBitmap[i]);
      }
    }

    this.totalInputsProcessed++;
    if (newEdges > 0) {
      this.totalEdgesDiscovered += newEdges;
      this.edgeDiscoveryTimeline.push({
        inputIndex: this.totalInputsProcessed,
        newEdges,
        totalEdges: this.totalEdgesDiscovered,
        timestamp: Date.now()
      });
    }

    return {
      isNovel: newEdges > 0,
      newEdges,
      totalEdges,
      totalGlobalEdges: this.totalEdgesDiscovered
    };
  }

  /**
   * Calculate coverage saturation rate using a sliding window.
   * When saturation approaches 1.0, fuzzing is unlikely to find
   * new paths and can be terminated (convergence detection).
   *
   * Based on the observation from Böhme et al. that coverage discovery
   * follows a power law distribution.
   *
   * @param {number} windowSize - number of recent inputs to consider
   * @returns {number} saturation rate [0, 1] where 1 = fully saturated
   */
  getSaturationRate(windowSize = 100) {
    if (this.totalInputsProcessed < windowSize) {
      return 0; // Not enough data
    }

    const recentDiscoveries = this.edgeDiscoveryTimeline.filter(
      d => d.inputIndex > this.totalInputsProcessed - windowSize
    );

    // Saturation = 1 - (new edges in window / window size)
    const discoveryRate = recentDiscoveries.length / windowSize;
    return 1 - discoveryRate;
  }

  /**
   * Get coverage statistics for reporting.
   */
  getStats() {
    let coveredEdges = 0;
    for (let i = 0; i < BITMAP_SIZE; i++) {
      if (this.globalBitmap[i] > 0) coveredEdges++;
    }

    return {
      coveredEdges,
      bitmapSize: BITMAP_SIZE,
      bitmapDensity: coveredEdges / BITMAP_SIZE,
      totalInputsProcessed: this.totalInputsProcessed,
      totalEdgesDiscovered: this.totalEdgesDiscovered,
      saturationRate: this.getSaturationRate(),
      discoveryTimeline: this.edgeDiscoveryTimeline.slice(-20) // last 20 events
    };
  }

  /**
   * Calculate Shannon entropy of the coverage bitmap.
   * Higher entropy indicates more diverse coverage exploration.
   *
   * H = -Σ p(x) * log2(p(x))
   *
   * Reference: Shannon, "A Mathematical Theory of Communication", 1948
   */
  getCoverageEntropy() {
    const bucketCounts = new Map();
    let nonZeroCount = 0;

    for (let i = 0; i < BITMAP_SIZE; i++) {
      if (this.globalBitmap[i] === 0) continue;
      nonZeroCount++;
      const bucket = bucketize(this.globalBitmap[i]);
      bucketCounts.set(bucket, (bucketCounts.get(bucket) || 0) + 1);
    }

    if (nonZeroCount === 0) return 0;

    let entropy = 0;
    for (const count of bucketCounts.values()) {
      const p = count / nonZeroCount;
      if (p > 0) {
        entropy -= p * Math.log2(p);
      }
    }

    return entropy;
  }
}
