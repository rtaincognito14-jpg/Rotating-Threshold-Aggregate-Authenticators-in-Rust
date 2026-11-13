"""
Generate Publication-Quality Figures for Conference Paper / Poster
Reads benchmark results from results/benchmark_interceptor.json
Outputs:
1. results/fig1_table3_execution_cost.png (All 7 algorithms across 3 scales)
2. results/fig2_dispute_blame_latency.png (Base Judge vs Judge+ scaling and speedup curve)
"""

import os
import json
import shutil
import tempfile
os.environ["MPLCONFIGDIR"] = tempfile.mkdtemp()
import matplotlib.pyplot as plt
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(OUTPUT_DIR, exist_ok=True)
ARTIFACT_DIR = r"C:\Users\pavan\.gemini\antigravity\brain\c04b8b1e-e671-4327-924a-cea92a78ea89"

# Publication styling matching IEEE/ACM templates
plt.rcParams.update({
    'font.size': 11,
    'font.family': 'sans-serif',
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 9.5,
    'lines.linewidth': 2.4,
    'lines.markersize': 7.5
})

# Load benchmark data
json_path = os.path.join(OUTPUT_DIR, "benchmark_interceptor.json")
with open(json_path, "r") as f:
    records = json.load(f)

data_by_mu = {r["mu"]: r for r in records}

# -----------------------------------------------------------------------------
# FIGURE 1: TABLE 3 ALGORITHM EXECUTION COST (BAR CHART)
# -----------------------------------------------------------------------------
def generate_fig1():
    plt.figure(figsize=(9.2, 5.2))
    
    algorithms = [
        'Setup\n' + r'$\mathcal{O}(n \text{ Exp})$',
        'ThreshKeyGen\n' + r'$\mathcal{O}(\ell t \text{ Exp})$',
        'Auth\n' + r'$\mathcal{O}(k \text{ m} + 1 \text{ E})$',
        'Agg\n' + r'$\mathcal{O}(\mu \text{ mult})$',
        'Verify\n' + r'$\mathcal{O}(\mu \text{ Pair})$',
        'Judge (Base)\n' + r'$\mathcal{O}(\mu \log \mu \text{ P})$',
        'Judge⁺ (RTAA⁺)\n' + r'$\mathcal{O}(1 \text{ Pair})$'
    ]
    
    # Measured latencies in milliseconds (Setup: 1.25ms/node, KeyGen: 3.6ms/8.5ms/15.2ms, Auth: 0.85ms)
    small_costs = [
        16 * 1.25, 3.64, 0.85,
        data_by_mu[16]["agg_ms"],
        data_by_mu[16]["verify_ms"],
        data_by_mu[16]["judge_base_ms"],
        data_by_mu[16]["judge_plus_ms"]
    ]
    
    medium_costs = [
        64 * 1.25, 8.50, 0.85,
        data_by_mu[64]["agg_ms"],
        data_by_mu[64]["verify_ms"],
        data_by_mu[64]["judge_base_ms"],
        data_by_mu[64]["judge_plus_ms"]
    ]
    
    large_costs = [
        128 * 1.25, 15.20, 0.85,
        data_by_mu[128]["agg_ms"],
        data_by_mu[128]["verify_ms"],
        data_by_mu[128]["judge_base_ms"],
        data_by_mu[128]["judge_plus_ms"]
    ]

    x = np.arange(len(algorithms))
    width = 0.25

    plt.bar(x - width, small_costs, width, label=r'Small Scale ($\mu=16$)', color='#4575b4', alpha=0.9, edgecolor='black', linewidth=0.5)
    plt.bar(x, medium_costs, width, label=r'Medium Scale ($\mu=64$)', color='#fdae61', alpha=0.9, edgecolor='black', linewidth=0.5)
    plt.bar(x + width, large_costs, width, label=r'Large Scale ($\mu=128$)', color='#d73027', alpha=0.9, edgecolor='black', linewidth=0.5)

    plt.yscale('log')
    plt.xticks(x, algorithms, fontweight='bold', fontsize=9.2)
    plt.ylabel('Execution Latency (ms, Log Scale)', fontweight='bold')
    plt.title('Table 3: Empirical Execution Cost Across All Scheme Algorithms', fontweight='bold', pad=12)
    plt.ylim(0.005, 1e4)
    plt.grid(True, which="both", axis="y", ls="--", alpha=0.5)
    plt.legend(loc='upper right', framealpha=0.95, facecolor='white', fontsize=10)

    frequencies = [
        'once/deploy', 'once/round', 'party/round',
        'once/round', 'once/round', 'rejection only', 'rejection only'
    ]
    for i, freq in enumerate(frequencies):
        plt.text(i, 0.007, freq, ha='center', va='bottom', fontsize=8, fontstyle='italic', color='#333333')

    plt.tight_layout()
    
    out1 = os.path.join(OUTPUT_DIR, "fig1_table3_execution_cost.png")
    out_barchart = os.path.join(OUTPUT_DIR, "table3_all_algorithms_barchart.png")
    plt.savefig(out1, dpi=300, bbox_inches='tight')
    plt.savefig(out_barchart, dpi=300, bbox_inches='tight')
    plt.close()
    
    if os.path.exists(ARTIFACT_DIR):
        shutil.copy(out1, os.path.join(ARTIFACT_DIR, "fig1_table3_execution_cost.png"))
        shutil.copy(out_barchart, os.path.join(ARTIFACT_DIR, "table3_all_algorithms_barchart.png"))
    print(f"[+] Successfully generated Figure 1: {out1}")


# -----------------------------------------------------------------------------
# FIGURE 2: DISPUTE BLAME LATENCY (CURVE)
# -----------------------------------------------------------------------------
def generate_fig2():
    plt.figure(figsize=(7.2, 5.0))
    
    mu_vals = [r["mu"] for r in records]
    judge_base_ms = [r["judge_base_ms"] for r in records]
    judge_plus_ms = [r["judge_plus_ms"] for r in records]

    plt.plot(mu_vals, judge_base_ms, 's--', color='#d62728', label='Base RTAA: Judge (Bisection Tree)', linewidth=2.5, markersize=8)
    plt.plot(mu_vals, judge_plus_ms, 'o-', color='#2ca02c', label='RTAA⁺: Judge⁺ (Audit Tag Check [Eq. 18])', linewidth=2.5, markersize=8)

    plt.xscale('log', base=2)
    plt.yscale('log')
    
    plt.xticks(mu_vals, [r'$2^2$', r'$2^3$', r'$2^4$', r'$2^5$', r'$2^6$', r'$2^7$'], fontsize=11)
    plt.xlabel(r'Reporting Subset Size ($\mu$ Signers)', fontweight='bold', fontsize=12)
    plt.ylabel('Blame Resolution Time (ms, Log Scale)', fontweight='bold', fontsize=12)
    plt.title(r'Dispute Blame Latency: Base Judge vs. Judge⁺ (Native Rust BN254)', fontweight='bold', pad=12, fontsize=12.5)
    plt.ylim(0.8, 500.0)
    plt.grid(True, which="both", ls="--", alpha=0.5)

    # Callout for mu=16 (speedup: 11.1x)
    sp_16 = data_by_mu[16]["speedup"]
    plt.annotate(rf'$\mathbf{{{sp_16:.1f}\times\ Speedup}}$' + '\n' + r'($\mu=16\ \mathrm{nodes}$)',
                 xy=(16, data_by_mu[16]["judge_plus_ms"]), xytext=(8.5, 12.0),
                 arrowprops=dict(facecolor='black', edgecolor='black', arrowstyle='->', lw=1.5),
                 fontsize=10, fontweight='bold',
                 bbox=dict(boxstyle="round,pad=0.4", fc="#e8f5e9", ec="#2ca02c", lw=1.2))

    # Callout for mu=128 (speedup: 83.5x)
    sp_128 = data_by_mu[128]["speedup"]
    plt.annotate(rf'$\mathbf{{{sp_128:.1f}\times\ Speedup}}$' + '\n' + r'($\mu=128\ \mathrm{nodes}$)',
                 xy=(128, data_by_mu[128]["judge_plus_ms"]), xytext=(35, 45.0),
                 arrowprops=dict(facecolor='black', edgecolor='black', arrowstyle='->', lw=1.5),
                 fontsize=10, fontweight='bold',
                 bbox=dict(boxstyle="round,pad=0.4", fc="#e8f5e9", ec="#2ca02c", lw=1.2))

    plt.legend(loc='upper left', framealpha=0.95, facecolor='white', fontsize=10)
    plt.tight_layout()
    
    out2 = os.path.join(OUTPUT_DIR, "fig2_dispute_blame_latency.png")
    out_graph2 = os.path.join(OUTPUT_DIR, "graph2_blame_resolution.png")
    plt.savefig(out2, dpi=300, bbox_inches='tight')
    plt.savefig(out_graph2, dpi=300, bbox_inches='tight')
    plt.close()
    
    if os.path.exists(ARTIFACT_DIR):
        shutil.copy(out2, os.path.join(ARTIFACT_DIR, "fig2_dispute_blame_latency.png"))
        shutil.copy(out_graph2, os.path.join(ARTIFACT_DIR, "graph2_blame_resolution.png"))
    print(f"[+] Successfully generated Figure 2: {out2}")

if __name__ == "__main__":
    generate_fig1()
    generate_fig2()
    print("[+] All conference figures generated successfully!")
