# PowerPoint Presentation Outline
**10+ Slides, 10 minutes presentation + 5 minutes Q&A**

## Slide 1: Title Slide
- **Title**: Comparative Analysis of String Pattern Matching Algorithms for Network Intrusion Detection
- **Course**: CSC 2400-002 Design of Algorithms Fall 2025
- **Team Members**: Whitten Smith, Avery Abad, Sean Southall
- **Date**: 12/01/2025

## Slide 2: Problem Overview
- **Visual**: Network traffic diagram or IDS architecture
- **Content**:
  - Network Intrusion Detection Systems need efficient pattern matching
  - Process large volumes of network flow data in real-time
  - Balance between performance and accuracy
- **Key Point**: Why pattern matching matters for IDS

## Slide 3: Research Questions
- **Visual**: Question marks or bullet points
- **Content**:
  1. How do advanced algorithms compare to brute force?
  2. What is the accuracy trade-off with pattern count?
  3. How do algorithms scale with text/pattern size?
  4. What is the optimal configuration?
- **Key Point**: Clear objectives before experiments

## Slide 4: Algorithms Implemented
- **Visual**: Algorithm logos or flowcharts
- **Content**:
  - **Brute Force** (Reference): O(nm) - baseline
  - **KMP**: O(n+m) worst-case, preprocessing
  - **Horspool**: Boyer-Moore variant, skip optimization
  - **RabinKarp**: Hash-based, rolling hash
- **Key Point**: Four algorithms with different approaches

## Slide 5: Experimental Design
- **Visual**: Table or diagram
- **Content**:
  - 6 real-world network flow datasets
  - 21,000 synthetic intrusions added
  - Text sizes: 1MB, 5MB, 10MB, 25MB
  - Pattern counts: 1, 5, 10, 20
  - 5 trials per configuration
  - 384 total experiments
- **Key Point**: Comprehensive experimental setup

## Slide 6: Key Results - Performance Comparison
- **Visual**: Bar chart (algorithm_comparison.png)
- **Content**:
  - Horspool: 1.05s (2.3x faster than brute force)
  - Brute Force: 2.47s (baseline)
  - KMP: 3.14s (slower)
  - RabinKarp: 10.81s (slowest)
- **Key Point**: Horspool is the clear winner

## Slide 7: Key Results - Accuracy
- **Visual**: Table or bar chart (dataset_comparison.png)
- **Content**:
  - 100% precision with 10 patterns
  - True positives: 165-7,921 depending on dataset
  - Detection rates: 4.2% to 42.1%
  - False positives increase dramatically with 20 patterns
- **Key Point**: Accuracy vs. pattern count trade-off

## Slide 8: Scalability Analysis
- **Visual**: Line graph (text_size_scaling.png)
- **Content**:
  - Execution time scales linearly with text size
  - Pattern count impact varies by algorithm
  - Horspool shows best scalability
- **Key Point**: How algorithms handle larger inputs

## Slide 9: Pattern Count Impact
- **Visual**: Dual graph (pattern_count_impact.png)
- **Content**:
  - Execution time increases with pattern count
  - True positives remain constant
  - False positives explode at 20 patterns
  - Optimal: 10 patterns
- **Key Point**: Finding the sweet spot

## Slide 10: Limitations and Future Work
- **Visual**: Bullet points or roadmap
- **Content**:
  - **Limitations**: 
    - Only sampled first 25MB
    - Simple string patterns
    - Single machine testing
  - **Future Work**:
    - Full dataset processing
    - Real attack signatures
    - Additional algorithms (Aho-Corasick)
    - Parallel implementations
- **Key Point**: Honest assessment and next steps

## Slide 11: Conclusion
- **Visual**: Summary diagram
- **Content**:
  - Horspool provides best performance (2.3x speedup)
  - All algorithms achieve 100% precision with 10 patterns
  - Optimal configuration: Horspool, 10 patterns, 25MB
  - Results validate theoretical expectations
- **Key Point**: Main takeaways

## Slide 12: Questions?
- **Visual**: Q&A graphic
- **Content**:
  - Thank you
  - Questions and Discussion
  - Contact information (optional)

---

## Presentation Tips

### Timing (10 minutes)
- **Slides 1-3**: 1.5 minutes (Introduction)
- **Slides 4-5**: 2 minutes (Methods)
- **Slides 6-9**: 4.5 minutes (Results - MAIN FOCUS)
- **Slides 10-11**: 1.5 minutes (Conclusion)
- **Slide 12**: 0.5 minutes (Q&A transition)

### Visual Guidelines
- **Use graphs from create_graphs.py**
- **Keep text minimal** - use bullet points
- **Large fonts** - readable from back of room
- **High contrast** - dark text on light background
- **Consistent color scheme** - use same colors across slides

### Q&A Preparation
- **Common Questions**:
  - Why is KMP slower than brute force?
  - How would results change with longer patterns?
  - What about memory usage?
  - Why only 4 algorithms?
  - How generalizable are these results?

### Speaker Notes
- Practice transitions between slides
- Know your numbers (memorize key statistics)
- Prepare explanations for each graph
- Have backup slides for detailed questions

---

## Backup Slides (Optional)

### Slide 13: Technical Details
- Compilation instructions
- System specifications
- Dataset characteristics

### Slide 14: Detailed Results Table
- Complete results table (if time permits)
- Reference for detailed questions

### Slide 15: Code Structure
- Brief overview of implementation
- Key functions and data structures

