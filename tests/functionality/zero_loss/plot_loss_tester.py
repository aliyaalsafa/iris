#!/usr/bin/env python3
import os
import re
import subprocess

import matplotlib.pyplot as plt  # make sure python3-matplotlib is installed


# Paths are relative to repo root (~/retina)
ZLT_PATH = "tests/functionality/zero_loss/zlt.py"
CONFIG_PATH = "configs/online.toml"

# Separate results file so we don't mix with other runs
OUTFILE = "zlt_loss_test_results.txt"

# *** SMALL TEST RUN ***
# Just try 0 and 10 flows so it finishes quickly
FLOW_COUNTS = [0, 10]


def run_one_zlt(num_flows: int, duration: int = 10):
    """
    Run zlt.py once for a given number of flows using the loss_test binary.
    duration is in seconds (short for test!).
    """
    label = f"flows_{num_flows}"

    cmd = [
        "python3",
        ZLT_PATH,
        "-b", "loss_test",
        "-d", str(duration),
        "-s", "512",                 # start nb_buckets (<= RSS_RETA_SIZE)
        "-c", CONFIG_PATH,
        "-m", "1",
        "-l", label,
        "-o", OUTFILE,
        "-a", f"--num-flows {num_flows} --warmup-ms 500 --uninstall-on-exit",
    ]

    print("\n=== Running ZLT for", num_flows, "flows ===")
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)


def parse_results(outfile: str):
    """
    Parse lines like:
      flows_1000: <1% Loss Throughput RESULT: 9.123e+09
    and return {num_flows: throughput_bps}.
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

            if label.startswith("flows_"):
                try:
                    num_flows = int(label.split("_", 1)[1])
                except ValueError:
                    continue
                # last run for a given label wins
                results[num_flows] = throughput_bps

    return results


def main():
    # Start with a clean results file for this test
    if os.path.exists(OUTFILE):
        print(f"Removing existing results file {OUTFILE}")
        os.remove(OUTFILE)

    # 1) Run ZLT for each flow count
    for num_flows in FLOW_COUNTS:
        run_one_zlt(num_flows)

    # 2) Parse results
    results = parse_results(OUTFILE)
    if not results:
        print("No results parsed from", OUTFILE)
        return

    # 3) Prepare data for plotting
    flows_sorted = sorted(results.keys())
    gbps = [results[n] / 1e9 for n in flows_sorted]

    print("\n=== Parsed results (Gbps) ===")
    for n, g in zip(flows_sorted, gbps):
        print(f"{n} flows -> {g:.3f} Gbps")

    # 4) Plot
    plt.figure()
    plt.plot(flows_sorted, gbps, marker="o")
    plt.xlabel("Number of pre-installed flows")
    plt.ylabel("Zero-loss throughput (Gbps)")
    plt.title("Zero-loss throughput vs number of flows (test run)")
    plt.grid(True)
    plt.ylim(0, 150)  # y-axis from 0 to 150 Gbps
    plt.tight_layout()
    plt.savefig("zero_loss_vs_flows_test.png", dpi=150)
    print("\nSaved plot to zero_loss_vs_flows_test.png")


if __name__ == "__main__":
    main()
