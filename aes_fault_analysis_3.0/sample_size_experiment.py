from pathlib import Path
import contextlib
import io

import pandas as pd
import matplotlib.pyplot as plt

# 复用已有恢复程序
from dfa_recover_attacker import (
    samples_from_dataframe,
    recover_round10,
    key_expansion_128,
    inv_key_schedule_128_from_round10,
)

# =========================================================
# 路径配置
# =========================================================
BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

MASTER_KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c"

# 每个样本数量重复次数
REPEAT_TIMES = 10

# 随机种子
BASE_RANDOM_SEED = 2026

# 默认样本数量
DEFAULT_SAMPLE_SIZES = [20, 40, 80, 120, 160, 240, 320]

# =========================================================
# 实验文件配置
# 注意：请确保这些文件名和 results 文件夹中的文件一致
# =========================================================
EXPERIMENT_FILES = {
    "A_wide": {
        "csv": RESULTS_DIR / "dfa_model_A_wide_attacker.csv",
        "model_type": "multi_bit_random",
        "display_name": "模型A-宽随机",
    },
    "A_ctrl": {
        "csv": RESULTS_DIR / "dfa_model_A_ctrl_attacker.csv",
        "model_type": "multi_bit_random",
        "display_name": "模型A-受控HW",
    },
    "B": {
        "csv": RESULTS_DIR / "dfa_model_B_attacker_good.csv",
        "model_type": "sparse_bit",
        "display_name": "模型B",
    },
    "C": {
        "csv": RESULTS_DIR / "dfa_model_C_attacker_good.csv",
        "model_type": "spatial_shift",
        "display_name": "模型C",
    },
    "D": {
        "csv": RESULTS_DIR / "dfa_model_D_attacker_good.csv",
        "model_type": "timing_jitter",
        "display_name": "模型D",
    },
}

# =========================================================
# 单次恢复
# =========================================================
def recover_once(df_sample: pd.DataFrame, model_type: str, round10_truth: bytes):
    samples = samples_from_dataframe(df_sample)

    # 屏蔽模型A恢复时的大量打印
    with contextlib.redirect_stdout(io.StringIO()):
        round10_key, round10_topn = recover_round10(samples, model_type, top_n=3)

    recovered_master = inv_key_schedule_128_from_round10(round10_key)

    correct_bytes = sum(
        1 for i, b in enumerate(round10_key)
        if b == round10_truth[i]
    )

    recovery_rate = correct_bytes / 16 * 100
    master_ok = recovered_master.hex() == MASTER_KEY_HEX

    return {
        "correct_bytes": correct_bytes,
        "recovery_rate": recovery_rate,
        "round10_key": round10_key.hex(),
        "recovered_master": recovered_master.hex(),
        "master_ok": master_ok,
    }

# =========================================================
# 单个模型样本数量实验
# =========================================================
def run_one_model_experiment(model_label: str, config: dict, round10_truth: bytes):
    csv_path = config["csv"]
    model_type = config["model_type"]
    display_name = config["display_name"]

    if not csv_path.exists():
        print(f"[跳过] {display_name}: 文件不存在 -> {csv_path}")
        return [], []

    df = pd.read_csv(csv_path)
    total_samples = len(df)

    sample_sizes = [n for n in DEFAULT_SAMPLE_SIZES if n <= total_samples]
    if total_samples not in sample_sizes:
        sample_sizes.append(total_samples)

    detail_rows = []
    summary_rows = []

    print(f"\n========== {display_name} ==========")
    print(f"文件: {csv_path.name}")
    print(f"总样本数: {total_samples}")
    print(f"测试样本数: {sample_sizes}")

    for n in sample_sizes:
        repeat_results = []

        for repeat_id in range(REPEAT_TIMES):
            random_state = BASE_RANDOM_SEED + repeat_id * 1000 + n

            if n == total_samples:
                df_sample = df.copy()
            else:
                df_sample = df.sample(
                    n=n,
                    replace=False,
                    random_state=random_state
                )

            result = recover_once(df_sample, model_type, round10_truth)
            repeat_results.append(result)

            detail_rows.append({
                "model": model_label,
                "display_name": display_name,
                "sample_size": n,
                "repeat_id": repeat_id,
                "correct_bytes": result["correct_bytes"],
                "recovery_rate": result["recovery_rate"],
                "round10_key": result["round10_key"],
                "recovered_master": result["recovered_master"],
                "master_ok": result["master_ok"],
            })

        rates = [r["recovery_rate"] for r in repeat_results]
        correct_bytes_list = [r["correct_bytes"] for r in repeat_results]

        avg_rate = sum(rates) / len(rates)
        min_rate = min(rates)
        max_rate = max(rates)

        avg_correct_bytes = sum(correct_bytes_list) / len(correct_bytes_list)
        min_correct_bytes = min(correct_bytes_list)
        max_correct_bytes = max(correct_bytes_list)

        summary_rows.append({
            "model": model_label,
            "display_name": display_name,
            "sample_size": n,
            "repeat_times": REPEAT_TIMES,
            "avg_correct_bytes": avg_correct_bytes,
            "min_correct_bytes": min_correct_bytes,
            "max_correct_bytes": max_correct_bytes,
            "avg_recovery_rate": avg_rate,
            "min_recovery_rate": min_rate,
            "max_recovery_rate": max_rate,
        })

        print(
            f"样本数 {n:>3}: "
            f"平均恢复 {avg_correct_bytes:.2f}/16, "
            f"平均恢复率 {avg_rate:.1f}%, "
            f"范围 {min_rate:.1f}% ~ {max_rate:.1f}%"
        )

    return detail_rows, summary_rows

# =========================================================
# 彩色折线图
# =========================================================
def plot_sample_size_results_color(df_summary: pd.DataFrame):
    if df_summary.empty:
        return

    plt.rcParams["font.sans-serif"] = ["SimHei"]
    plt.rcParams["axes.unicode_minus"] = False

    plt.figure(figsize=(9, 5.5))

    # 彩色论文风格：不同颜色 + 不同线型 + 不同点型
    style_map = {
        "模型A-宽随机": {"linestyle": "-",  "marker": "o", "color": "tab:red"},
        "模型A-受控HW": {"linestyle": "--", "marker": "s", "color": "tab:blue"},
        "模型B":       {"linestyle": "-.", "marker": "^", "color": "tab:green"},
        "模型C":       {"linestyle": ":",  "marker": "D", "color": "tab:orange"},
        "模型D":       {"linestyle": "-",  "marker": "x", "color": "tab:purple"},
    }

    # 固定显示顺序
    plot_order = ["模型A-宽随机", "模型A-受控HW", "模型B", "模型C", "模型D"]

    for display_name in plot_order:
        group = df_summary[df_summary["display_name"] == display_name].copy()
        if group.empty:
            continue

        group = group.sort_values("sample_size")
        style = style_map.get(
            display_name,
            {"linestyle": "-", "marker": "o", "color": "tab:blue"}
        )

        plt.plot(
            group["sample_size"],
            group["avg_recovery_rate"],
            linestyle=style["linestyle"],
            marker=style["marker"],
            color=style["color"],
            linewidth=1.8,
            markersize=6,
            markerfacecolor="white",
            markeredgecolor=style["color"],
            markeredgewidth=1.2,
            label=display_name,
        )

    plt.xlabel("样本数量")
    plt.ylabel("平均恢复率 / %")
    plt.title("不同样本数量下第 10 轮轮密钥恢复率对比")
    plt.ylim(-5, 105)
    plt.xlim(0, 330)
    plt.xticks([20, 40, 80, 120, 160, 200, 240, 280, 320])
    plt.grid(True, linestyle="--", linewidth=0.5, color="0.7")
    plt.legend(frameon=True, edgecolor="black")
    plt.tight_layout()

    out_path = RESULTS_DIR / "sample_size_recovery_curve_color.png"
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close()

    print(f"\n已生成彩色恢复率变化图: {out_path}")

# =========================================================
# 主流程
# =========================================================
def main():
    master_key_bytes = bytes.fromhex(MASTER_KEY_HEX)
    round10_truth = key_expansion_128(master_key_bytes)[10]

    all_detail_rows = []
    all_summary_rows = []

    for model_label, config in EXPERIMENT_FILES.items():
        detail_rows, summary_rows = run_one_model_experiment(
            model_label=model_label,
            config=config,
            round10_truth=round10_truth,
        )

        all_detail_rows.extend(detail_rows)
        all_summary_rows.extend(summary_rows)

    df_detail = pd.DataFrame(all_detail_rows)
    df_summary = pd.DataFrame(all_summary_rows)

    detail_path = RESULTS_DIR / "sample_size_experiment_detail.csv"
    summary_path = RESULTS_DIR / "sample_size_experiment_summary.csv"

    df_detail.to_csv(detail_path, index=False, encoding="utf-8-sig")
    df_summary.to_csv(summary_path, index=False, encoding="utf-8-sig")

    print(f"\n已生成详细结果: {detail_path}")
    print(f"已生成汇总结果: {summary_path}")

    plot_sample_size_results_color(df_summary)

if __name__ == "__main__":
    main()