#!/usr/bin/env python3
import os
import re
import subprocess
import statistics

import matplotlib.pyplot as plt  # make sure python3-matplotlib is installed


# Paths are relative to repo root (~/retina)
ZLT_PATH = "tests/functionality/zero_loss/zlt.py"
CONFIG_PATH = "configs/online.toml"

# Results file
OUTFILE = "zlt_loss_test_results.txt"

# Experiment parameters
DURATION = 15  # seconds per trial

FLOW_COUNTS = [
    0,
    10,
    100,
    1000,
    100000,
    200000,
    500000,
    750000,
    1000000,
    #2000000,
]


def run_one_zlt(num_flows: int, duration: int = DURATION):
    """
    Run zlt.py once for a given number of flows using the loss_test binary.
    Single trial per flow count; label encodes only the num_flows.
    """
    label = f"flows_{num_flows}"

    cmd = [
        "python3",
        ZLT_PATH,
        "-b",
        "loss_test",
        "-d",
        str(duration),
        "-s",
        "512",  # nb_buckets start value
        "-c",
        CONFIG_PATH,
        "-m",
        "8",
        "-l",
        label,
        "-o",
        OUTFILE,
        "-a",
        f"--num-flows {num_flows} --warmup-ms 500 --uninstall-on-exit",
    ]

    print("\n=== Running ZLT for", num_flows, "flows ===")
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)


def parse_results(outfile: str):
    """
    Parse lines like:
      flows_1000: <1% Loss Throughput RESULT: 7.20577e+10
    and return {num_flows: [throughput_bps1, throughput_bps2, ...]}.
    (We keep a list in case you re-use the same OUTFILE across runs.)
    """
    pattern = re.compile(
        r"^(?P<label>[^:]+):\s*<\d+% Loss Throughput RESULT:\s*(?P<throughput>[0-9.eE+-]+)"
    )
    results = {}

    if not os.path.exists(outfile):
        print(f"Results file {outfile} does not exist")
        return results

    with open(outfile, "r") as f:
        for line in f:
            m = pattern.search(line)
            if not m:
                continue
            label = m.group("label").strip()
            throughput_bps = float(m.group("throughput"))

            # Skip runs where throughput was never parsed and stayed negative
            if throughput_bps < 0:
                continue

            # Expect labels like "flows_1000"
            if label.startswith("flows_"):
                parts = label.split("_")
                if len(parts) < 2:
                    continue
                try:
                    num_flows = int(parts[1])
                except ValueError:
                    continue

                results.setdefault(num_flows, []).append(throughput_bps)

    return results


def main():
    # Start with a clean results file for this experiment
    if os.path.exists(OUTFILE):
        print(f"Removing existing results file {OUTFILE}")
        os.remove(OUTFILE)

    # 1) Run ZLT for each flow count (single trial per flow count)
    for num_flows in FLOW_COUNTS:
        run_one_zlt(num_flows)

    # 2) Parse results
    results = parse_results(OUTFILE)
    if not results:
        print("No results parsed from", OUTFILE)
        return

    # 3) Aggregate: compute mean Gbps (and std dev) per flow count
    flows_sorted = sorted(results.keys())
    mean_gbps = []
    std_gbps = []

    print("\n=== Parsed results per flow count ===")
    for n in flows_sorted:
        vals_bps = results[n]
        vals_gbps = [v / 1e9 for v in vals_bps]
        mean_val = sum(vals_gbps) / len(vals_gbps)
        mean_gbps.append(mean_val)

        if len(vals_gbps) > 1:
            std_val = statistics.stdev(vals_gbps)
        else:
            std_val = 0.0
        std_gbps.append(std_val)

        print(f"{n} flows -> mean {mean_val:.3f} Gbps over {len(vals_gbps)} run(s)")

    # 4) Plot: flows on x-axis, mean Gbps on y-axis with error bars (std dev usually 0)
    plt.figure()
    plt.errorbar(
        flows_sorted,
        mean_gbps,
        yerr=std_gbps,
        fmt="o-",
        capsize=4,
    )
    plt.xscale("log")  # helpful since flow counts span several orders of magnitude
    plt.xlabel("Number of pre-installed flows (log scale)")
    plt.ylabel("Zero-loss throughput (Gbps)")
    plt.title(
        f"Zero-loss throughput vs number of flows\n"
        f"1 trial per flow count, {DURATION}s each"
    )
    plt.grid(True, which="both", linestyle="--", alpha=0.5)
    plt.ylim(0, 150)  # fixed y-axis range as requested
    plt.tight_layout()
    plt.savefig("zero_loss_vs_flows_single_trial.png", dpi=150)
    print("\nSaved plot to zero_loss_vs_flows_single_trial.png")


if __name__ == "__main__":
    main()
