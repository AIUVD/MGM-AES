"""Five candidate rank curves for d1 -> d4; the focus is not the physical key."""
import json
from pathlib import Path
import numpy as np
from scipy.io import savemat
from exploit_pred_2 import attack_indices, rank_compute
from rank_results import stable_zero_trace, plot_rank_curves


def perform_attacks(predictions, plaintext, config, output):
    p = np.asarray(predictions, dtype=np.float64)
    plaintext = np.asarray(plaintext)
    if p.ndim != 2 or p.shape[1] != 256 or len(p) != len(plaintext):
        raise ValueError('Expected (N,256) probabilities aligned with plaintext.')
    if (plaintext.shape != (len(p), 16) or not np.issubdtype(plaintext.dtype, np.integer)
            or np.any(plaintext < 0) or np.any(plaintext > 255)):
        raise ValueError('Expected (N,16) plaintext bytes.')
    if not np.isfinite(p).all() or np.any(p < 0) or not np.allclose(p.sum(1), 1, atol=1e-4):
        raise ValueError('Invalid prediction probabilities.')
    spec = config['target_spec']
    indices = attack_indices(len(p), config['attack_traces'], config['attacks'], config['attack_seed'])
    logp = np.log(p + 1e-40)
    mean = np.zeros((config['attack_traces'], 256), dtype=np.float64)
    selected = np.empty((config['attacks'], config['attack_traces'], len(spec['values'])))
    for i, idx in enumerate(indices):
        ranks = rank_compute(logp[idx], plaintext[idx], byte=0)
        mean += ranks / len(indices)
        selected[i] = ranks[:, spec['values']]
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    np.save(output / 'attack_indices.npy', indices)
    np.save(output / 'attack_target_ranks.npy', selected)
    np.save(output / 'true_key_ranks.npy', selected[:, :, 0])
    return save_rank_results(output, mean[None], selected[None], spec,
                             [config['seed']], [config['attack_seed']])


def save_rank_results(output, experiment_mean_ranks, attack_target_ranks, spec,
                      training_seeds, attack_seeds):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    runs = np.asarray(experiment_mean_ranks, dtype=np.float64)
    selected = np.asarray(attack_target_ranks, dtype=np.float64)
    keys, names, focus = spec['values'], spec['names'], spec['focus_index']
    if runs.ndim != 3 or runs.shape[2] != 256 or min(runs.shape[:2]) < 1:
        raise ValueError('Expected (experiments,traces,256) mean ranks.')
    experiments, traces, _ = runs.shape
    if (len(keys) != 5 or len(names) != 5 or focus != 4 or keys[0] != spec['k4']
            or any(not 0 <= k < 256 for k in keys)):
        raise ValueError('Invalid d1/d4 candidate specification.')
    if (selected.ndim != 4 or selected.shape[0] != experiments or selected.shape[1] < 1
            or selected.shape[2:] != (traces, 5)):
        raise ValueError('Expected (experiments,attacks,traces,5) candidate ranks.')
    if len(training_seeds) != experiments or len(attack_seeds) != experiments:
        raise ValueError('Wrong number of experiment seeds.')
    if not np.isfinite(runs).all() or not np.isfinite(selected).all():
        raise ValueError('Ranks must be finite.')
    # Averaging 100 exact ranks can round the mathematical upper bound of 255
    # a few ulps above 255 (for example 255.00000000000045). Allow only this
    # numerical noise, reject substantive errors, then restore the valid bounds.
    rank_tolerance = 1e-9
    if (np.any(runs < -rank_tolerance) or np.any(runs > 255 + rank_tolerance)
            or np.any(selected < -rank_tolerance)
            or np.any(selected > 255 + rank_tolerance)):
        raise ValueError('Ranks must be between 0 and 255 (outside rounding tolerance).')
    runs = np.clip(runs, 0.0, 255.0)
    selected = np.clip(selected, 0.0, 255.0)
    per_experiment = selected.mean(axis=1)
    if not np.allclose(runs[:, :, keys], per_experiment, rtol=1e-10, atol=1e-10):
        raise ValueError('Candidate ranks disagree with individual attacks.')
    mean = runs.mean(axis=0)
    target_mean = per_experiment.mean(axis=0)
    mean[:, keys] = target_mean
    focus_curve = target_mean[:, focus]
    stable = stable_zero_trace(focus_curve)
    run_times = [stable_zero_trace(row[:, focus]) for row in per_experiment]
    attack_times = [[stable_zero_trace(row[:, focus]) for row in run] for run in selected]
    focus_zero_rate = (selected[:, :, :, focus] == 0).mean(axis=(0, 1))
    physical_zero_rate = (selected[:, :, :, 0] == 0).mean(axis=(0, 1))
    summary = dict(
        experiment_count=experiments, attacks_per_experiment=selected.shape[1],
        total_attack_count=experiments * selected.shape[1], traces_per_attack=traces,
        target_byte=0, correct_key=spec['k4'], target_spec=spec,
        focus_name=names[focus], focus_key=keys[focus], focus_stable_zero_trace=stable,
        experiment_focus_stable_zero_traces=run_times,
        attack_focus_stable_zero_traces=attack_times,
        focus_final_mean_rank=float(focus_curve[-1]),
        focus_final_zero_rank_rate=float(focus_zero_rate[-1]),
        final_target_mean_ranks=target_mean[-1].tolist(),
        physical_key_final_mean_rank=float(target_mean[-1, 0]),
        observation_limit=traces,
        aggregation='Equal-weight mean of per-experiment mean ranks, not model probabilities',
        rank_convention='0 is best; averaged ties; trace counts start at 1',
        convergence_definition='First trace after which focus rank stays exactly 0 THROUGH THE OBSERVATION LIMIT',
        missing_convergence='JSON null / MATLAB NaN means not reached within the observation window')
    (output / 'attack_summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    np.save(output / 'mean_ranks.npy', mean)
    np.save(output / 'target_mean_ranks.npy', target_mean)
    np.save(output / 'focus_rank.npy', focus_curve)
    np.save(output / 'guessing_entropy.npy', target_mean[:, 0])
    np.save(output / 'success_rate.npy', physical_zero_rate)
    np.save(output / 'experiment_mean_ranks.npy', runs)
    # Each single run also has attack_target_ranks.npy with shape (attacks,traces,5).
    np.save(output / 'experiment_attack_target_ranks.npy', selected)
    nan_time = lambda t: np.nan if t is None else float(t)
    savemat(str(output / 'rank_results.mat'), dict(
        trace_counts=np.arange(1, traces + 1, dtype=np.int32),
        key_hypotheses=np.arange(256, dtype=np.int32),
        mean_rank=mean, experiment_mean_rank=runs,
        target_names=np.asarray(names, dtype=object), target_keys=np.asarray(keys, dtype=np.int32),
        target_mean_rank=target_mean, experiment_target_mean_rank=per_experiment,
        attack_target_rank=selected, focus_name=names[focus], focus_key=np.int32(keys[focus]),
        focus_column=np.int32(focus + 1), focus_rank=focus_curve,
        focus_stable_zero_trace=nan_time(stable),
        experiment_focus_stable_zero_trace=np.array([nan_time(t) for t in run_times]),
        attack_focus_stable_zero_trace=np.array([[nan_time(t) for t in run] for run in attack_times]),
        focus_zero_rank_rate=focus_zero_rate,
        correct_key=np.int32(spec['k4']), target_byte=np.int32(0),
        mean_true_rank=target_mean[:, 0], success_rate=physical_zero_rate,
        training_seeds=np.asarray(training_seeds, dtype=np.uint32),
        attack_seeds=np.asarray(attack_seeds, dtype=np.uint32),
        experiment_count=np.int32(experiments), attacks_per_experiment=np.int32(selected.shape[1]),
        traces_per_attack=np.int32(traces), observation_limit=np.int32(traces),
        rank_convention='0 is best; key k is mean_rank column k+1 in MATLAB; target columns follow target_names',
        convergence_definition=summary['convergence_definition']),
        do_compression=True, oned_as='column', long_field_names=True)
    plot_rank_curves(mean, keys[focus], output,
                     f'{experiments} training runs, {selected.shape[1]} attacks each; focus: {names[focus]}',
                     target_keys=keys, target_names=names)
    status = f'from trace {stable} through {traces}' if stable is not None else f'not reached within {traces} traces'
    print(f'Focus {names[focus]}={keys[focus]:#04x}: rank stays 0 {status}.')
    return summary


def aggregate_experiments(run_dirs, output):
    configs, means, selected = [], [], []
    reference = None
    for directory in map(Path, run_dirs):
        config = json.loads((directory / 'config.json').read_text(encoding='utf-8'))
        summary = json.loads((directory / 'attack_summary.json').read_text(encoding='utf-8'))
        signature = {k: config[k] for k in ['target_spec', 'sample_ranges', 'train_h5', 'attack_h5',
                                            'profile_num', 'attack_pool', 'attacks', 'attack_traces']}
        if reference is not None and signature != reference:
            raise ValueError('Incompatible experiment datasets, windows, candidates or attack sizes.')
        if summary['experiment_count'] != 1 or summary['target_spec'] != config['target_spec']:
            raise ValueError('Expected a completed single experiment.')
        reference = signature
        configs.append(config)
        means.append(np.load(directory / 'mean_ranks.npy'))
        selected.append(np.load(directory / 'attack_target_ranks.npy'))
    if not configs:
        raise ValueError('No experiments to aggregate.')
    return save_rank_results(output, np.stack(means), np.stack(selected), reference['target_spec'],
                             [c['seed'] for c in configs], [c['attack_seed'] for c in configs])
