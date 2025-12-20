#!/usr/bin/env node

/**
 * Simple ML Filter - No complex dependencies!
 * Uses TF-IDF for text similarity (proven to work)
 */

import fs from 'fs/promises';
import { logger } from './utils/logger.js';

class SimpleTFIDFFilter {
  constructor() {
    // Known vulnerability patterns (simple text)
    this.knownVulns = [
      {
        id: 'CVE-2021-21353',
        text: 'prototype pollution template options eval code execution block property',
        severity: 'critical'
      },
      {
        id: 'CVE-2020-8203',
        text: 'prototype pollution merge defaultsdeep lodash proto object deep',
        severity: 'high'
      },
      {
        id: 'CVE-2022-46175',
        text: 'prototype pollution json parse proto property injection',
        severity: 'high'
      },
      {
        id: 'CVE-2021-23337',
        text: 'template injection options pollution eval code execution ejs',
        severity: 'critical'
      },
      {
        id: 'CVE-2020-7598',
        text: 'prototype pollution argument parsing minimist proto command line',
        severity: 'medium'
      }
    ];

    this.idf = this.calculateIDF();
  }

  // Calculate IDF (Inverse Document Frequency)
  calculateIDF() {
    const allWords = new Set();
    const docFreq = new Map();

    for (const vuln of this.knownVulns) {
      const words = new Set(this.tokenize(vuln.text));
      words.forEach(word => {
        allWords.add(word);
        docFreq.set(word, (docFreq.get(word) || 0) + 1);
      });
    }

    const idf = new Map();
    const numDocs = this.knownVulns.length;

    for (const word of allWords) {
      idf.set(word, Math.log(numDocs / (docFreq.get(word) || 1)));
    }

    return idf;
  }

  tokenize(text) {
    return text.toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 2);
  }

  // Calculate TF-IDF vector
  calculateTFIDF(text) {
    const words = this.tokenize(text);
    const tf = new Map();

    words.forEach(word => {
      tf.set(word, (tf.get(word) || 0) + 1);
    });

    const vector = new Map();
    for (const [word, count] of tf) {
      const termFreq = count / words.length;
      const idf = this.idf.get(word) || 0;
      vector.set(word, termFreq * idf);
    }

    return vector;
  }

  // Cosine similarity between two TF-IDF vectors
  cosineSimilarity(vec1, vec2) {
    let dotProduct = 0;
    let mag1 = 0;
    let mag2 = 0;

    const allWords = new Set([...vec1.keys(), ...vec2.keys()]);

    for (const word of allWords) {
      const v1 = vec1.get(word) || 0;
      const v2 = vec2.get(word) || 0;

      dotProduct += v1 * v2;
      mag1 += v1 * v1;
      mag2 += v2 * v2;
    }

    if (mag1 === 0 || mag2 === 0) return 0;
    return dotProduct / (Math.sqrt(mag1) * Math.sqrt(mag2));
  }

  chainToText(chain) {
    return `${chain.description} ${chain.type} ${chain.sink?.name || ''} ${chain.source?.property || ''} risk ${chain.riskLevel}`;
  }

  async filter(resultsFile) {
    logger.info(`🧠 Simple ML filtering (TF-IDF): ${resultsFile}`);

    const content = await fs.readFile(resultsFile, 'utf8');
    const results = JSON.parse(content);
    const chains = results.potentialChains || [];

    const filtered = {
      highConfidence: [],
      mediumConfidence: [],
      lowConfidence: [],
      falsePositive: []
    };

    for (const chain of chains) {
      // Pre-filter obvious false positives
      if (this.isDefinitelyFalse(chain)) {
        filtered.falsePositive.push(chain);
        continue;
      }

      // Calculate similarity to known vulnerabilities
      const chainText = this.chainToText(chain);
      const chainVec = this.calculateTFIDF(chainText);

      let maxSimilarity = 0;
      let bestMatch = null;

      for (const vuln of this.knownVulns) {
        const vulnVec = this.calculateTFIDF(vuln.text);
        const similarity = this.cosineSimilarity(chainVec, vulnVec);

        if (similarity > maxSimilarity) {
          maxSimilarity = similarity;
          bestMatch = vuln;
        }
      }

      // Classify based on similarity
      chain.mlSimilarity = maxSimilarity;
      chain.mlMatch = bestMatch?.id;

      if (maxSimilarity >= 0.5 && chain.riskLevel >= 7) {
        filtered.highConfidence.push(chain);
      } else if (maxSimilarity >= 0.3 && chain.riskLevel >= 5) {
        filtered.mediumConfidence.push(chain);
      } else if (maxSimilarity >= 0.2 || chain.riskLevel >= 4) {
        filtered.lowConfidence.push(chain);
      } else {
        filtered.falsePositive.push(chain);
      }
    }

    this.printReport(filtered, chains.length);
    return filtered;
  }

  isDefinitelyFalse(chain) {
    if (chain.source?.type === 'simulated_pollution') return true;
    if (chain.source?.type === 'mock_pollution') return true;
    if (!chain.sink || chain.sink === 'unknown') return true;
    if (chain.riskLevel < 3) return true;
    return false;
  }

  printReport(filtered, total) {
    console.log('\n' + '='.repeat(70));
    console.log('🧠 SIMPLE ML FILTERING REPORT (TF-IDF)');
    console.log('='.repeat(70));

    console.log(`\nTotal Chains: ${total}`);
    console.log(`✅ High Confidence: ${filtered.highConfidence.length}`);
    console.log(`⚠️  Medium Confidence: ${filtered.mediumConfidence.length}`);
    console.log(`ℹ️  Low Confidence: ${filtered.lowConfidence.length}`);
    console.log(`❌ False Positives: ${filtered.falsePositive.length}`);

    const fpRate = Math.round((filtered.falsePositive.length / total) * 100);
    const actionable = filtered.highConfidence.length + filtered.mediumConfidence.length;

    console.log('\n' + '─'.repeat(70));
    console.log(`FALSE POSITIVE RATE: ${fpRate}%`);
    console.log(`ACTIONABLE FINDINGS: ${actionable}`);
    console.log('='.repeat(70));

    if (filtered.highConfidence.length > 0) {
      console.log('\n🎯 HIGH CONFIDENCE FINDINGS:');
      filtered.highConfidence.forEach((chain, i) => {
        console.log(`\n${i + 1}. ${chain.description}`);
        console.log(`   Risk: ${chain.riskLevel}/10`);
        console.log(`   Similarity: ${(chain.mlSimilarity * 100).toFixed(1)}%`);
        console.log(`   Similar to: ${chain.mlMatch}`);
      });
    }
  }
}

// CLI
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log(`
🧠 Simple ML Filter (TF-IDF - No complex dependencies!)

Usage:
  node src/simple-ml-filter.js <results-file.json>

Example:
  node src/simple-ml-filter.js results/pug/results-*.json

Uses TF-IDF for similarity matching - works everywhere!
No native dependencies required.
`);
    process.exit(0);
  }

  const filter = new SimpleTFIDFFilter();
  const filtered = await filter.filter(args[0]);

  // Save results
  const outputFile = args[0].replace('.json', '-simple-ml-filtered.json');
  await fs.writeFile(outputFile, JSON.stringify(filtered, null, 2));
  logger.info(`\n💾 Saved to: ${outputFile}`);
}

export { SimpleTFIDFFilter };
