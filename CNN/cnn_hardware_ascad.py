"""Apply the synchronized ASCAD CNN of Zaid et al. to custom HDF5 captures.

See README_zh.md for data layouts, commands and experimental differences.
"""
import argparse
from datetime import datetime
import json
import math
from pathlib import Path
import secrets

import h5py
import numpy as np
import tensorflow as tf
from tensorflow import keras

from aes import AES_Sbox
from exploit_pred_2 import perform_attacks
from one_cycle import OneCycleLR
from h5_data import H5Source, TraceBatches, fit_streaming, transform
from rank_results import save_rank_results, aggregate_experiments

BASE = Path(__file__).resolve().parent
PRESET = dict(blocks=[(4, 1, 2)], dense=[10, 10], batch_size=50,
              max_lr=5e-3, attack_traces=100, preprocessing='standard-minmax')


def cnn_architecture(input_size=700, learning_rate=None):
    preset = PRESET
    remaining = input_size
    for _, _, pool in preset['blocks']:
        remaining //= pool
    if remaining < 1:
        raise ValueError('Trace length is too short for the selected pooling layers.')
    inputs = keras.layers.Input((input_size, 1), name='trace')
    x = inputs
    for i, (filters, kernel, pool) in enumerate(preset['blocks'], 1):
        x = keras.layers.Conv1D(filters, kernel, padding='same', activation='selu',
                               kernel_initializer='he_uniform', name=f'block{i}_conv1')(x)
        x = keras.layers.BatchNormalization(name=f'block{i}_bn')(x)
        x = keras.layers.AveragePooling1D(pool, strides=pool, name=f'block{i}_pool')(x)
    x = keras.layers.Flatten(name='flatten')(x)
    for i, units in enumerate(preset['dense'], 1):
        x = keras.layers.Dense(units, activation='selu', kernel_initializer='he_uniform',
                              name=f'fc{i}')(x)
    outputs = keras.layers.Dense(256, activation='softmax', name='predictions')(x)
    model = keras.Model(inputs, outputs, name='ascad_sync')
    model.compile(optimizer=keras.optimizers.Adam(
        learning_rate=preset['max_lr'] if learning_rate is None else learning_rate),
        loss='categorical_crossentropy', metrics=['accuracy'], jit_compile=False)
    return model


def load_data(config, role):
    """Small-array compatibility helper; training uses H5Source batches instead."""
    source = H5Source(config, role)
    return source.read(slice(0, source.count)), source.labels, source.plaintext, source.key


def fit_preprocessing(x, method):
    if method == 'none':
        return dict(method=np.array(method))
    # Only profiling data are used, including its validation subset, as in the author code.
    mean = np.mean(x, axis=0, dtype=np.float64)
    std = np.std(x, axis=0, dtype=np.float64)
    std[std < 1e-12] = 1.0
    stats = dict(method=np.array(method), mean=mean, std=std)
    if method == 'standard-minmax':
        low = (np.min(x, axis=0) - mean) / std
        span = (np.max(x, axis=0) - mean) / std - low
        span[span < 1e-12] = 1.0
        stats.update(low=low, span=span)
    return stats


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')


def evaluate(model, config, stats, output):
    source = H5Source(config, 'attack')
    plaintext, key = source.plaintext, source.key
    predictions = np.empty((source.count, 256), dtype=np.float32)
    for begin in range(0, source.count, config['batch_size']):
        end = min(source.count, begin + config['batch_size'])
        x = transform(source.read(slice(begin, end)), stats)[..., None]
        predictions[begin:end] = np.asarray(model(x, training=False))
    np.save(output / 'predictions.npy', predictions)
    np.save(output / 'attack_plaintext.npy', plaintext)
    mean_ranks = perform_attacks(
        config['attack_traces'], predictions, config['attacks'], plaintext, key,
        byte=config['byte'], seed=config['attack_seed'], savefig=False,
        filename=model.name, output_dir=output)
    true_ranks = np.load(output / 'true_key_ranks.npy')
    return save_rank_results(output, mean_ranks[None, ...], true_ranks[None, ...],
                             key, config['byte'], [config['seed']], [config['attack_seed']])


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=['train-attack', 'train', 'attack', 'check'], default='train-attack')
    p.add_argument('--data-format', choices=['ascad', 'custom'], default='custom')
    p.add_argument('--data', help='Official ASCAD HDF5 path; relative paths use the CNN directory.')
    p.add_argument('--train-h5', help='Default: 50000.h5 next to this script.')
    p.add_argument('--attack-h5', help='Default: 10000.h5 next to this script.')
    p.add_argument('--model-dir', help='Existing run directory; required for --mode attack.')
    p.add_argument('--output', help='New output directory; existing nonempty directories are rejected.')
    p.add_argument('--trace-start', type=int, help='Zero-based start; custom default 2400 (point 2401).')
    p.add_argument('--trace-length', type=int, help='Number of samples; default 700 (custom points 2401-3100).')
    p.add_argument('--byte', type=int, help='Zero-based target byte (ASCAD: 2, custom: 0).')
    p.add_argument('--key', type=lambda s: int(s, 0), help='Target key BYTE, e.g. 0 or 0x00; read separately from each file /key by default.')
    p.add_argument('--profile-num', type=int, help='Total profiling rows INCLUDING validation.')
    p.add_argument('--validation-num', type=int, help='Validation rows within profiling pool; custom default 1000.')
    p.add_argument('--epochs', type=int, default=50)
    p.add_argument('--experiments', type=int, default=10, help='Independent training runs; default 10. Attack/check modes use one saved model/no training.')
    p.add_argument('--batch-size', type=int)
    p.add_argument('--max-lr', type=float)
    p.add_argument('--preprocessing', choices=['standard-minmax', 'standard', 'none'])
    p.add_argument('--attack-pool', type=int)
    p.add_argument('--attack-traces', type=int)
    p.add_argument('--attacks', type=int)
    p.add_argument('--seed', type=int, help='Base training seed; omitted => generate a fresh base. Each experiment gets a distinct seed.')
    p.add_argument('--attack-seed', type=int, help='Base sampling seed; default 0. Each training experiment gets a distinct attack seed.')
    p.add_argument('--deterministic', action='store_true', help='Enable TensorFlow deterministic operations.')
    return p


def resolve_path(value):
    path = Path(value)
    return str(path.resolve() if path.is_absolute() else (BASE / path).resolve())


def make_config(args):
    c = vars(args).copy()
    preset = PRESET
    custom = args.data_format == 'custom'
    defaults = dict(trace_start=2400 if custom else 0, trace_length=700, byte=0 if custom else 2,
                    profile_num=10000 if custom else 50000,
                    validation_num=1000 if custom else 5000, batch_size=preset['batch_size'],
                    max_lr=preset['max_lr'], preprocessing=preset['preprocessing'],
                    attack_pool=10000, attack_traces=preset['attack_traces'],
                    attacks=100, attack_seed=0)
    for name, value in defaults.items():
        if c[name] is None:
            c[name] = value
    c['seed'] = secrets.randbits(32) if args.seed is None else args.seed
    c['data'] = resolve_path(args.data or 'ASCAD_dataset/ASCAD.h5')
    c['train_h5'] = resolve_path(args.train_h5 or '50000.h5')
    c['attack_h5'] = resolve_path(args.attack_h5 or '10000.h5')
    return c


def validate_config(c):
    for field in ['experiments', 'profile_num', 'epochs', 'batch_size', 'attack_pool', 'attack_traces', 'attacks']:
        if c[field] <= 0:
            raise ValueError(f'{field} must be positive.')
    if c['trace_length'] is not None and c['trace_length'] < 2:
        raise ValueError('trace_length must be at least 2.')
    if not 0 < c['validation_num'] < c['profile_num']:
        raise ValueError('Require 0 < validation_num < profile_num.')
    if c['trace_start'] < 0 or c['byte'] < 0 or c['max_lr'] <= 0:
        raise ValueError('Invalid trace start, byte or learning rate.')
    if c['key'] is not None and not 0 <= c['key'] <= 255:
        raise ValueError('key must be a byte in [0, 255].')
    if not 0 <= c['seed'] < 2**32 or not 0 <= c['attack_seed'] < 2**32:
        raise ValueError('Seeds must be in [0, 2**32).')
    if c['attack_traces'] > c['attack_pool']:
        raise ValueError('attack_traces cannot exceed attack_pool.')
    if c['data_format'] == 'custom' and Path(c['train_h5']) == Path(c['attack_h5']):
        raise ValueError('Custom training and attack files must be distinct.')


def _run_single(argv=None, shared_stats=None):
    args = parser().parse_args(argv)
    config = make_config(args)
    if args.mode == 'attack':
        if not args.model_dir:
            raise ValueError('--mode attack requires --model-dir.')
        model_dir = Path(resolve_path(args.model_dir))
        config = json.loads((model_dir / 'config.json').read_text(encoding='utf-8'))
        # Reuse the saved architecture, byte, key and preprocessing. Only attack
        # inputs and sampling controls can be changed in attack-only mode.
        for field in ['data', 'attack_h5']:
            if getattr(args, field) is not None:
                config[field] = resolve_path(getattr(args, field))
        for field in ['attack_pool', 'attack_traces', 'attacks', 'attack_seed']:
            if getattr(args, field) is not None:
                config[field] = getattr(args, field)
        config.update(mode='attack', model_dir=str(model_dir))
    config['experiments'] = 1
    validate_config(config)
    sources = {}
    if args.mode != 'attack':
        sources['profile'] = H5Source(config, 'profile')
        config['trace_length'] = sources['profile'].length
    if args.mode != 'train':
        sources['attack'] = H5Source(config, 'attack')
    for source in sources.values():
        source.read(slice(0, min(2, source.count)))
        if source.report.get('full_window_false_count', 0):
            print(f"Capture note: {source.path}: {source.report['full_window_false_count']} selected traces have full_window=False (whole-trigger flag; it does not assess the selected analysis window).")
    output = Path(resolve_path(args.output)) if args.output else BASE / 'outputs' / (
        datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '_ascad_sync')
    if output.exists() and any(output.iterdir()):
        raise ValueError(f'Output directory is not empty: {output}')
    output.mkdir(parents=True, exist_ok=True)
    config['output'] = str(output)
    write_json(output / 'config.json', config)
    write_json(output / 'data_report.json', {role: source.report for role, source in sources.items()})
    write_json(output / 'environment.json', dict(tensorflow=tf.__version__, keras=keras.__version__,
                                                numpy=np.__version__, h5py=h5py.__version__))
    if args.mode == 'check':
        print(json.dumps({role: source.report for role, source in sources.items()}, indent=2))
        print(f'Checks passed; no training performed. Output: {output}')
        return output
    if config['deterministic']:
        tf.config.experimental.enable_op_determinism()
    keras.utils.set_random_seed(config['seed'])
    print(f'Training seed: {config["seed"]}; attack seed: {config["attack_seed"]}')
    if args.mode == 'attack':
        model = keras.models.load_model(model_dir / 'model.keras')
        with np.load(model_dir / 'preprocessing.npz', allow_pickle=False) as stored:
            stats = dict(stored)
    else:
        source = sources['profile']
        order = np.random.default_rng(config['seed']).permutation(source.count)
        split = source.count - config['validation_num']
        train_idx, val_idx = order[:split], order[split:]
        np.savez(output / 'split_indices.npz', train=train_idx, validation=val_idx)
        if shared_stats is None:
            print('Computing profiling statistics in bounded-memory chunks...')
            stats = fit_streaming(source, config['preprocessing'])
        else:
            print('Reusing profiling statistics for the same profiling pool and window.')
            stats = shared_stats
        np.savez(output / 'preprocessing.npz', **stats)
        train_batches = TraceBatches(source, train_idx, stats, config['batch_size'],
                                     shuffle=True, seed=config['seed'])
        val_batches = TraceBatches(source, val_idx, stats, config['batch_size'])
        model = cnn_architecture(config['trace_length'], config['max_lr'])
        model.summary()
        summary_lines = []
        model.summary(print_fn=summary_lines.append)
        (output / 'model_summary.txt').write_text('\n'.join(summary_lines), encoding='utf-8')
        steps = math.ceil(split / config['batch_size'])
        cycle = OneCycleLR(config['max_lr'], steps * config['epochs'])
        history = model.fit(
            train_batches, validation_data=val_batches,
            epochs=config['epochs'], shuffle=False,
            callbacks=[cycle, keras.callbacks.ModelCheckpoint(str(output / 'model.keras'))], verbose=2)
        write_json(output / 'history.json', {k: [float(v) for v in values] for k, values in history.history.items()})
        np.save(output / 'learning_rates.npy', cycle.rates)
    if args.mode != 'train':
        evaluate(model, config, stats, output)
    print(f'Output: {output}')
    return output


def experiment_seeds(base, count, stride):
    # Odd stride gives distinct uint32 seeds for up to 2**32 runs; first uses base.
    return [(base + i * stride) % 2**32 for i in range(count)]


def main(argv=None):
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parser().parse_args(argv)
    # Loading a model is never interpreted as ten new training experiments.
    if args.mode in ('attack', 'check'):
        return _run_single(argv)
    config = make_config(args)
    validate_config(config)
    if args.experiments == 1:
        keras.backend.clear_session()
        return _run_single(argv)
    if args.experiments > 2**32:
        raise ValueError('Too many experiments for distinct uint32 seeds.')
    # Validate both datasets before starting a long multi-experiment job.
    profile = H5Source(config, 'profile')
    config['trace_length'] = profile.length
    if args.mode == 'train-attack':
        H5Source(config, 'attack')
    output = Path(resolve_path(args.output)) if args.output else BASE / 'outputs' / (
        datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '_ascad_sync_experiments')
    if output.exists() and any(output.iterdir()):
        raise ValueError(f'Output directory is not empty: {output}')
    output.mkdir(parents=True, exist_ok=True)
    config['output'] = str(output)
    write_json(output / 'config.json', config)
    training_seeds = experiment_seeds(config['seed'], args.experiments, 104729)
    attack_seeds = experiment_seeds(config['attack_seed'], args.experiments, 130363)
    manifest = dict(status='running', requested_experiments=args.experiments,
                    base_training_seed=config['seed'], base_attack_seed=config['attack_seed'],
                    experiments=[dict(index=i + 1, directory=f'experiment_{i+1:02d}',
                                      training_seed=training_seeds[i], attack_seed=attack_seeds[i],
                                      status='pending') for i in range(args.experiments)])
    write_json(output / 'experiments.json', manifest)
    run_dirs, stats = [], None
    try:
        for i, entry in enumerate(manifest['experiments']):
            entry['status'] = 'running'
            write_json(output / 'experiments.json', manifest)
            print(f"\n=== Independent training {i+1}/{args.experiments}; seed={training_seeds[i]}, attack seed={attack_seeds[i]} ===")
            keras.backend.clear_session()
            run = _run_single([*argv, '--experiments', '1', '--seed', str(training_seeds[i]),
                               '--attack-seed', str(attack_seeds[i]),
                               '--output', str(output / entry['directory'])], shared_stats=stats)
            run_dirs.append(run)
            if stats is None:
                with np.load(run / 'preprocessing.npz', allow_pickle=False) as saved:
                    stats = dict(saved)
            entry['status'] = 'complete'
            write_json(output / 'experiments.json', manifest)
        if args.mode == 'train-attack':
            aggregate_experiments(run_dirs, output)
        manifest['status'] = 'complete'
        write_json(output / 'experiments.json', manifest)
    except Exception as error:
        manifest['status'] = 'failed'
        manifest['error'] = str(error)
        for entry in manifest['experiments']:
            if entry['status'] == 'running':
                entry['status'] = 'failed'
        write_json(output / 'experiments.json', manifest)
        raise
    print(f'Completed {args.experiments} independent training runs. Output: {output}')
    return output


if __name__ == '__main__':
    main()
