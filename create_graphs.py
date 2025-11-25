#!/usr/bin/env python3
"""
Graph Generation Script for Project Results
Creates visualizations from CSV result files
"""

import pandas as pd
import matplotlib.pyplot as plt
import os
from pathlib import Path

def load_results(dataset_dir, algorithm, size, pattern_count):
    """Load results from CSV file"""
    csv_file = f"{dataset_dir}/{algorithm}_{size}_p{pattern_count}.csv"
    if os.path.exists(csv_file):
        return pd.read_csv(csv_file)
    return None

def create_execution_time_comparison():
    """Compare execution times across algorithms"""
    dataset = "results/fri_morning_updated"
    size = "25MB"
    pattern_count = 10
    
    algorithms = ["brute", "kmp", "horspool", "rabin"]
    times = []
    labels = []
    
    for algo in algorithms:
        df = load_results(dataset, algo, size, pattern_count)
        if df is not None:
            avg_time = df['execution_seconds'].mean()
            times.append(avg_time)
            labels.append(algo.upper())
    
    plt.figure(figsize=(10, 6))
    bars = plt.bar(labels, times, color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728'])
    plt.ylabel('Execution Time (seconds)', fontsize=12)
    plt.xlabel('Algorithm', fontsize=12)
    plt.title(f'Algorithm Performance Comparison\n({size}, {pattern_count} patterns)', fontsize=14, fontweight='bold')
    plt.grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for bar, time in zip(bars, times):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                f'{time:.2f}s', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig('results/algorithm_comparison.png', dpi=300, bbox_inches='tight')
    print("Saved: results/algorithm_comparison.png")
    plt.close()

def create_text_size_scaling():
    """Show how execution time scales with text size"""
    dataset = "results/fri_morning_updated"
    algorithm = "brute"
    pattern_count = 10
    
    sizes = ["1MB", "5MB", "10MB", "25MB"]
    times = []
    
    for size in sizes:
        df = load_results(dataset, algorithm, size, pattern_count)
        if df is not None:
            avg_time = df['execution_seconds'].mean()
            times.append(avg_time)
    
    plt.figure(figsize=(10, 6))
    plt.plot(sizes, times, marker='o', linewidth=2, markersize=8, color='#1f77b4')
    plt.ylabel('Execution Time (seconds)', fontsize=12)
    plt.xlabel('Text Size', fontsize=12)
    plt.title(f'Execution Time vs Text Size\n({algorithm.upper()}, {pattern_count} patterns)', 
              fontsize=14, fontweight='bold')
    plt.grid(alpha=0.3)
    
    # Add value labels
    for size, time in zip(sizes, times):
        plt.text(size, time + 0.05, f'{time:.2f}s', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig('results/text_size_scaling.png', dpi=300, bbox_inches='tight')
    print("Saved: results/text_size_scaling.png")
    plt.close()

def create_pattern_count_impact():
    """Show impact of pattern count on performance"""
    dataset = "results/fri_morning_updated"
    algorithm = "brute"
    size = "25MB"
    
    pattern_counts = [1, 5, 10, 20]
    times = []
    true_positives = []
    false_positives = []
    
    for pc in pattern_counts:
        df = load_results(dataset, algorithm, size, pc)
        if df is not None:
            times.append(df['execution_seconds'].mean())
            true_positives.append(df['true_positives'].mean())
            false_positives.append(df['false_positives'].mean())
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Execution time
    ax1.plot(pattern_counts, times, marker='o', linewidth=2, markersize=8, color='#1f77b4')
    ax1.set_ylabel('Execution Time (seconds)', fontsize=12)
    ax1.set_xlabel('Pattern Count', fontsize=12)
    ax1.set_title('Execution Time vs Pattern Count', fontsize=13, fontweight='bold')
    ax1.grid(alpha=0.3)
    
    # Accuracy
    ax2.plot(pattern_counts, true_positives, marker='o', linewidth=2, markersize=8, 
             label='True Positives', color='#2ca02c')
    ax2.plot(pattern_counts, false_positives, marker='s', linewidth=2, markersize=8, 
             label='False Positives', color='#d62728')
    ax2.set_ylabel('Count', fontsize=12)
    ax2.set_xlabel('Pattern Count', fontsize=12)
    ax2.set_title('True vs False Positives', fontsize=13, fontweight='bold')
    ax2.legend()
    ax2.grid(alpha=0.3)
    ax2.set_yscale('log')  # Log scale for better visualization
    
    plt.tight_layout()
    plt.savefig('results/pattern_count_impact.png', dpi=300, bbox_inches='tight')
    print("Saved: results/pattern_count_impact.png")
    plt.close()

def create_dataset_comparison():
    """Compare true positives across datasets"""
    datasets = {
        "Friday Morning": "fri_morning_updated",
        "Tuesday": "tue_working_hours_updated",
        "Thursday Morning": "thu_morning_webattacks_updated",
        "Wednesday": "wed_working_hours_updated"
    }
    
    algorithm = "brute"
    size = "25MB"
    pattern_count = 10
    
    dataset_names = []
    true_positives = []
    
    for name, dir_name in datasets.items():
        dataset_dir = f"results/{dir_name}"
        df = load_results(dataset_dir, algorithm, size, pattern_count)
        if df is not None:
            tp = df['true_positives'].mean()
            if tp > 0:  # Only include datasets with detections
                dataset_names.append(name)
                true_positives.append(tp)
    
    plt.figure(figsize=(10, 6))
    bars = plt.bar(dataset_names, true_positives, color='#2ca02c')
    plt.ylabel('True Positives', fontsize=12)
    plt.xlabel('Dataset', fontsize=12)
    plt.title(f'True Positive Detection Across Datasets\n({algorithm.upper()}, {size}, {pattern_count} patterns)', 
              fontsize=14, fontweight='bold')
    plt.grid(axis='y', alpha=0.3)
    
    # Add value labels
    for bar, tp in zip(bars, true_positives):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 50,
                f'{int(tp)}', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig('results/dataset_comparison.png', dpi=300, bbox_inches='tight')
    print("Saved: results/dataset_comparison.png")
    plt.close()

def main():
    """Generate all graphs"""
    print("Generating graphs from results...")
    print("=" * 50)
    
    # Create results directory if it doesn't exist
    os.makedirs('results', exist_ok=True)
    
    try:
        create_execution_time_comparison()
        create_text_size_scaling()
        create_pattern_count_impact()
        create_dataset_comparison()
        
        print("=" * 50)
        print("All graphs generated successfully!")
        print("Graphs saved in results/ directory")
        
    except Exception as e:
        print(f"Error generating graphs: {e}")
        print("Make sure you have matplotlib and pandas installed:")
        print("  pip install matplotlib pandas")

if __name__ == "__main__":
    main()

