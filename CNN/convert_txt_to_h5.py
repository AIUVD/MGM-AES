"""Convert d1/d4 hexadecimal wave.txt/plain.txt into root-level HDF5 datasets.

Standalone: only numpy and h5py are required. Default root is this script's
directory, so place it in F:/data and run: python convert_txt_to_h5.py
Use --limit 10000 to convert only the first 10,000 traces of each dataset.
"""
import argparse
import ast
from datetime import datetime, timezone
import json
from pathlib import Path
import h5py
import numpy as np


def read_key_groups(path):
    """Parse literal key/rk assignments without executing the text file."""
    groups, pending = [], None
    for node in ast.parse(Path(path).read_text(encoding='utf-8-sig')).body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1 and
                isinstance(node.targets[0], ast.Name) and node.targets[0].id in ('key', 'rk')):
            raise ValueError('Key file must contain only key/rk literal assignments.')
        name, value = node.targets[0].id, node.value
        if isinstance(value, ast.Call):
            if not (isinstance(value.func, ast.Name) and value.func.id == 'bytearray' and
                    len(value.args) == 1 and not value.keywords):
                raise ValueError('Only bytearray([...]) literals are allowed in key file.')
            value = value.args[0]
        values = ast.literal_eval(value)
        if not isinstance(values, (list, tuple)) or len(values) != 16 or any(type(v) is not int or not 0 <= v <= 255 for v in values):
            raise ValueError('Each key/rk must contain exactly 16 byte values.')
        if name == 'key':
            if pending is not None:
                raise ValueError('Missing rk after key.')
            pending = np.array(values, dtype=np.uint8)
        else:
            if pending is None:
                raise ValueError('rk must follow its key.')
            groups.append((pending, np.array(values, dtype=np.uint8)))
            pending = None
    if pending is not None or len(groups) != 4:
        raise ValueError('Expected exactly four complete key/rk groups.')
    return groups


def read_plaintext(path):
    rows = []
    with Path(path).open(encoding='ascii') as f:
        for number, line in enumerate(f, 1):
            try:
                row = [int(value, 16) for value in line.split()]
            except ValueError as error:
                raise ValueError(f'{path}: non-hexadecimal plaintext on line {number}') from error
            if len(row) != 16 or any(not 0 <= v <= 255 for v in row):
                raise ValueError(f'{path}: line {number} must contain 16 hexadecimal bytes.')
            rows.append(row)
    if not rows:
        raise ValueError(f'Empty plaintext file: {path}')
    return np.asarray(rows, dtype=np.uint8)


def decode_wave(line, samples, source, number):
    tokens = line.split()
    if len(tokens) != samples:
        raise ValueError(f'{source}: line {number} has {len(tokens)} samples, expected {samples}.')
    try:
        row = np.fromiter((int(token, 16) for token in tokens), dtype=np.int64, count=samples)
    except (ValueError, OverflowError) as error:
        raise ValueError(f'{source}: invalid hexadecimal sample on line {number}.') from error
    if np.any(row < 0) or np.any(row > 2**24):
        raise ValueError('Samples must be nonnegative integers exactly representable as float32 (<= 2**24).')
    return row.astype(np.float32)


def convert_dataset(folder, output, key, rk, group_number, samples=10000, limit=0, batch_rows=64):
    folder, output = Path(folder), Path(output)
    if samples < 1 or batch_rows < 1 or limit < 0:
        raise ValueError('Invalid samples, batch_rows or limit.')
    plaintext = read_plaintext(folder / 'plain.txt')
    available = len(plaintext)
    if limit > available:
        raise ValueError(f'{folder}: only {available} plaintext rows, requested {limit}.')
    count = limit or available
    partial = output.with_name(output.name + '.partial')
    if output.exists() or partial.exists():
        raise FileExistsError(f'Refusing to overwrite {output} or {partial}. Choose a new output directory.')
    output.parent.mkdir(parents=True, exist_ok=True)
    wave = folder / 'wave.txt'
    anchors = {}
    print(f'{folder.name}: {count}/{available} traces, {samples} samples each -> {output}', flush=True)
    with h5py.File(partial, 'x') as f, wave.open('rb') as source:
        f.attrs.update(complete=False, num_captured=0, samples=samples,
                       requested_traces=count, available_plaintext_rows=available,
                       source_folder=str(folder.resolve()), source_wave=str(wave.resolve()),
                       source_plaintext=str((folder / 'plain.txt').resolve()),
                       source_number_base=16, key_group=group_number,
                       dataset_name=folder.name, key_mode='fixed',
                       trace_units='Raw ADC integer counts decoded from hexadecimal; no physical calibration',
                       created_utc=datetime.now(timezone.utc).isoformat())
        traces = f.create_dataset('traces', (count, samples), dtype='f4', chunks=(1, samples))
        f.create_dataset('plaintext', data=plaintext[:count], dtype='u1')
        keys = f.create_dataset('key', (count, 16), dtype='u1')
        rks = f.create_dataset('rk', (count, 16), dtype='u1')
        f.create_dataset('trace_index', data=np.arange(count, dtype=np.uint64))
        for begin in range(0, count, batch_rows):
            end = min(count, begin + batch_rows)
            block = np.empty((end - begin, samples), dtype=np.float32)
            for i in range(begin, end):
                line = source.readline()
                if not line:
                    raise ValueError(f'{wave}: ended at {i} traces; expected {count}.')
                block[i - begin] = decode_wave(line, samples, wave, i + 1)
                if i in (0, count // 2, count - 1):
                    anchors[i] = block[i - begin].copy()
            traces[begin:end] = block
            keys[begin:end] = np.broadcast_to(key, (end - begin, 16))
            rks[begin:end] = np.broadcast_to(rk, (end - begin, 16))
            f.attrs.modify('num_captured', end)
            if begin == 0 or end == count or end // 1000 != begin // 1000:
                print(f'{folder.name}: {end}/{count}', flush=True)
        if count == available and source.readline():
            raise ValueError(f'{wave}: more trace rows than plaintext rows.')
        for i, expected in anchors.items():
            np.testing.assert_array_equal(traces[i], expected)
        np.testing.assert_array_equal(f['plaintext'][:], plaintext[:count])
        np.testing.assert_array_equal(f['key'][0], key)
        np.testing.assert_array_equal(f['rk'][-1], rk)
        f.attrs.modify('complete', True)
    if output.exists():
        raise FileExistsError(f'Output appeared during conversion: {output}; complete data remain at {partial}.')
    partial.rename(output)
    print(f'Validated and saved {output}', flush=True)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output-dir', type=Path, help='Default: root; writes d1.h5 and d4.h5.')
    parser.add_argument('--key-file', type=Path, help='Default: root/key&rk.txt.')
    parser.add_argument('--limit', type=int, default=0, help='First N traces per dataset; 0 = all.')
    parser.add_argument('--samples', type=int, default=10000)
    parser.add_argument('--batch-rows', type=int, default=64)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    output = args.output_dir.resolve() if args.output_dir else root
    groups = read_key_groups(args.key_file or root / 'key&rk.txt')
    for name, group in [('d1', 1), ('d4', 4)]:
        if (output / f'{name}.h5').exists() or (output / f'{name}.h5.partial').exists():
            raise FileExistsError(f'Output already exists for {name}; no files converted.')
        for file in ['wave.txt', 'plain.txt']:
            if not (root / name / file).is_file():
                raise FileNotFoundError(root / name / file)
    for name, group in [('d1', 1), ('d4', 4)]:
        key, rk = groups[group - 1]
        convert_dataset(root / name, output / f'{name}.h5', key, rk, group,
                        args.samples, args.limit, args.batch_rows)
    k1, r1 = int(groups[0][0][0]), int(groups[0][1][0])
    k4, r4 = int(groups[3][0][0]), int(groups[3][1][0])
    print(json.dumps({'k4': k4, 'k1': k1, 'k1^rk1': k1 ^ r1,
                      'k4^rk4': k4 ^ r4, 'k4^rk1^rk4': k4 ^ r1 ^ r4}, indent=2))


if __name__ == '__main__':
    main()
