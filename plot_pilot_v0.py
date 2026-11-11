#!/usr/bin/python3
"""Optional Matplotlib figure from verified v0 summary.json; never load BPF."""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--output-prefix", type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.summary.read_text())
    if data.get("schema") != "sentinel-pilot-analysis-v0" or data.get("valid_seeds") != 30:
        raise SystemExit("Use the verified thirty-seed v0 summary.")
    paths = [args.output_prefix.with_suffix(suffix) for suffix in (".png", ".svg")]
    if any(path.exists() for path in paths):
        raise SystemExit("A figure already exists; choose a new output prefix.")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                         "svg.fonttype": "none", "svg.hashsalt": "sentinel-pilot-v0"})
    labels = {"ignore_inode": "Ignore inode", "requested_path_identity": "Requested pathname",
              "basename_identity": "Basename"}
    style = {"random": ("#3562A6", "-", "o"), "guided": ("#C35D14", "--", "s")}
    lookup = {(row["mutant"], row["strategy"]): row for row in data["distributions"]}
    fig, axes = plt.subplots(1, 3, figsize=(12, 4.6), sharey=True)
    fig.subplots_adjust(left=0.07, right=0.98, top=0.77, bottom=0.25, wspace=0.13)
    for ax, (mutant, title) in zip(axes, labels.items()):
        for strategy, (color, line, marker) in style.items():
            row = lookup[mutant, strategy]
            x = [0, 1, 2, 3, 4]
            y = [0] + [row["detected_by_" + str(n)] for n in range(1, 5)]
            ax.step(x, y, where="post", color=color, linestyle=line, linewidth=2, label=strategy.title())
            ax.plot(x[1:], y[1:], color=color, linestyle="none", marker=marker, markersize=4)
        ax.set_title(title, fontsize=11, fontweight="bold", pad=12)
        ax.set_xlim(0, 4.12)
        ax.set_ylim(0, 31.5)
        ax.set_xticks(range(5))
        ax.set_yticks(range(0, 31, 5))
        ax.set_xlabel("Selected tests")
        ax.grid(axis="y", alpha=0.22)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].set_ylabel("Seeds with a detected mismatch (out of 30)")
    fig.suptitle("Detection within the four-test budget", x=0.07, y=0.98,
                 ha="left", fontsize=16, fontweight="bold")
    fig.text(0.07, 0.89, "30 paired seeds; two confirmation repetitions per seed, counted once.", fontsize=10)
    handles, names = axes[0].get_legend_handles_labels()
    fig.legend(handles, names, loc="lower left", bbox_to_anchor=(0.062, 0.10),
               ncol=2, frameon=False)
    fig.text(0.07, 0.065, "Undetected at step 4 remains censored. Calibration and smoke runs are separate.", fontsize=9)
    fig.text(0.07, 0.025, "Seven fixed development fixtures; three planted faults; one Linux VM/kernel.", fontsize=9, color="#444444")
    paths[0].parent.mkdir(parents=True, exist_ok=True)
    creator = "Matplotlib " + matplotlib.__version__ + "; plot_pilot_v0.py"
    fig.savefig(paths[0], dpi=180, metadata={"Software": creator})
    fig.savefig(paths[1], metadata={"Date": None, "Creator": creator})
    # Matplotlib path attributes contain harmless trailing spaces; keep Git diffs clean.
    paths[1].write_text("\n".join(line.rstrip() for line in paths[1].read_text().splitlines()) + "\n")
    plt.close(fig)
    print("Figure created with Matplotlib", matplotlib.__version__)
    for path in paths:
        print(path)


if __name__ == "__main__":
    main()
