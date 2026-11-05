"""Rank aggregation, sustained-zero statistics and MATLAB export."""
import json
from pathlib import Path
import numpy as np
from scipy.io import savemat


def stable_zero_trace(curve):
    """1-based trace count after the last nonzero rank, or None if censored."""
    curve = np.asarray(curve, dtype=np.float64)
    if curve.ndim != 1 or curve.size == 0 or not np.isfinite(curve).all() or np.any(curve < 0):
        raise ValueError('Rank curve must be a nonempty finite nonnegative vector.')
    if curve[-1] != 0:
        return None
    nonzero = np.flatnonzero(curve != 0)
    return int(nonzero[-1] + 2) if len(nonzero) else 1


def plot_rank_curves(mean_ranks, correct_key, output, title,
                     target_keys=None, target_names=None):
    import matplotlib
    matplotlib.use('Agg')
    from matplotlib import pyplot as plt
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8, 5))
    counts = np.arange(1, len(mean_ranks) + 1)
    ax.plot(counts, mean_ranks, color='gray', alpha=0.12, linewidth=0.4)
    keys = [correct_key] if target_keys is None else list(target_keys)
    names = ['true key'] if target_names is None else list(target_names)
    if len(keys) != len(names):
        raise ValueError('target_keys and target_names lengths differ.')
    for key, name in zip(keys, names):
        ax.plot(counts, mean_ranks[:, key], label=f'{name}: {key:#04x}', linewidth=2)
    start = stable_zero_trace(mean_ranks[:, correct_key])
    if start is not None:
        ax.axvline(start, linestyle='--', color='tab:green',
                   label=f'Rank stays 0 from trace {start}')
    else:
        ax.text(0.02, 0.95, f'No sustained rank 0 within {len(counts)} traces',
                transform=ax.transAxes, va='top')
    ax.set(xlabel='Number of traces', ylabel='Mean rank (0 = best)',
           title=title, ylim=(-2, 256))
    ax.grid(True)
    ax.legend()
    fig.tight_layout()
    fig.savefig(output / 'rank.png', dpi=180)
    fig.savefig(output / 'rank.pdf')
    plt.close(fig)


def save_rank_results(output, experiment_mean_ranks, true_key_ranks,
                      correct_key, target_byte, training_seeds, attack_seeds):
    """Equal-weight average of experiment rank curves, never model predictions.

    Shapes: experiment_mean_ranks=(experiments,traces,256),
    true_key_ranks=(experiments,attacks,traces).
    MATLAB vectors are stored as columns, missing convergence times as NaN.
    """
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    runs = np.asarray(experiment_mean_ranks, dtype=np.float64)
    true = np.asarray(true_key_ranks, dtype=np.float64)
    if runs.ndim != 3 or runs.shape[2] != 256 or runs.shape[0] < 1 or runs.shape[1] < 1:
        raise ValueError('experiment_mean_ranks must have shape (experiments, traces, 256).')
    experiments, traces, _ = runs.shape
    if true.ndim != 3 or true.shape[0] != experiments or true.shape[1] < 1 or true.shape[2] != traces:
        raise ValueError('true_key_ranks must have shape (experiments, attacks, traces).')
    if not 0 <= correct_key < 256 or len(training_seeds) != experiments or len(attack_seeds) != experiments:
        raise ValueError('Invalid key or seed counts.')
    if (not np.isfinite(runs).all() or not np.isfinite(true).all() or
            np.any(runs < 0) or np.any(true < 0)):
        raise ValueError('Ranks must be finite and nonnegative.')
    experiment_ge = true.mean(axis=1)
    if not np.allclose(runs[:, :, correct_key], experiment_ge, rtol=1e-10, atol=1e-10):
        raise ValueError('Per-experiment mean ranks disagree with individual true-key ranks.')
    mean_ranks = runs.mean(axis=0)
    # Use this shared value in both exported arrays to avoid tiny roundoff differences.
    mean_ge = experiment_ge.mean(axis=0)
    mean_ranks[:, correct_key] = mean_ge
    success_rate = (true == 0).mean(axis=(0, 1))
    stable = stable_zero_trace(mean_ge)
    per_experiment = [stable_zero_trace(row) for row in experiment_ge]
    per_attack = [[stable_zero_trace(row) for row in run] for run in true]
    flat_times = [time for run in per_attack for time in run]
    summary = dict(
        experiment_count=experiments, attacks_per_experiment=int(true.shape[1]),
        total_attack_count=experiments * int(true.shape[1]), traces_per_attack=traces,
        target_byte=int(target_byte), correct_key=int(correct_key),
        final_ge=float(mean_ge[-1]), final_success_rate=float(success_rate[-1]),
        best_mean_rank_key=int(np.argmin(mean_ranks[-1])),
        stable_zero_trace=stable, experiment_stable_zero_traces=per_experiment,
        attack_stable_zero_traces=per_attack,
        unrecovered_attack_count=sum(t is None for t in flat_times),
        mean_attack_stable_zero_trace=(float(np.mean(flat_times)) if all(t is not None for t in flat_times) else None),
        observation_limit=traces,
        aggregation='Equal-weight arithmetic mean of per-experiment mean rank curves',
        rank_convention='zero-based ranks with averaged ties; trace counts are one-based',
        missing_convergence='null in JSON / NaN in MATLAB means not sustained at zero within the observed window')
    (output / 'attack_summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    np.save(output / 'mean_ranks.npy', mean_ranks)
    np.save(output / 'guessing_entropy.npy', mean_ge)
    np.save(output / 'success_rate.npy', success_rate)
    if experiments > 1:
        np.save(output / 'experiment_mean_ranks.npy', runs)
        np.save(output / 'experiment_guessing_entropy.npy', experiment_ge)
    savemat(str(output / 'rank_results.mat'), dict(
        trace_counts=np.arange(1, traces + 1, dtype=np.int32),
        key_hypotheses=np.arange(256, dtype=np.int32),
        correct_key=np.int32(correct_key), target_byte=np.int32(target_byte),
        mean_rank=mean_ranks, mean_true_rank=mean_ge, success_rate=success_rate,
        experiment_mean_rank=runs, experiment_true_rank=experiment_ge,
        attack_true_rank=true,
        stable_zero_trace=np.nan if stable is None else float(stable),
        experiment_stable_zero_trace=np.array([np.nan if t is None else t for t in per_experiment]),
        attack_stable_zero_trace=np.array([[np.nan if t is None else t for t in run] for run in per_attack]),
        training_seeds=np.asarray(training_seeds, dtype=np.uint32),
        attack_seeds=np.asarray(attack_seeds, dtype=np.uint32),
        experiment_count=np.int32(experiments), attacks_per_experiment=np.int32(true.shape[1]),
        traces_per_attack=np.int32(traces),
        rank_convention='rank 0 is best; key k is MATLAB column k+1; trace_counts are 1-based',
        aggregation='Equal-weight average of per-experiment mean rank curves'),
        do_compression=True, oned_as='column', long_field_names=True)
    plot_rank_curves(mean_ranks, correct_key, output,
                     f'{experiments} training experiment(s), {true.shape[1]} attacks each')
    status = f'from trace {stable}' if stable is not None else f'not reached within {traces} traces'
    print(f'Mean correct-key rank stays 0: {status}. Final GE={mean_ge[-1]:.6g}')
    return summary


def aggregate_experiments(run_dirs, output):
    """Require compatible, complete experiments before generating a final result."""
    ranks, true_ranks, configs, reference = [], [], [], None
    for directory in run_dirs:
        directory = Path(directory)
        config = json.loads((directory / 'config.json').read_text(encoding='utf-8'))
        summary = json.loads((directory / 'attack_summary.json').read_text(encoding='utf-8'))
        signature = tuple(summary[k] for k in ['correct_key', 'target_byte', 'traces_per_attack', 'attacks_per_experiment'])
        if reference is not None and signature != reference:
            raise ValueError('Experiments differ in key, target byte or attack dimensions.')
        reference = signature
        ranks.append(np.load(directory / 'mean_ranks.npy'))
        true_ranks.append(np.load(directory / 'true_key_ranks.npy'))
        configs.append(config)
    if not ranks:
        raise ValueError('No completed experiments to aggregate.')
    return save_rank_results(output, np.stack(ranks), np.stack(true_ranks),
                             reference[0], reference[1],
                             [c['seed'] for c in configs], [c['attack_seed'] for c in configs])
