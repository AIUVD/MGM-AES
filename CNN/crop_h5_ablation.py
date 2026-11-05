"""Crop d1.h5/d4.h5 into the four requested windows for the ablation runs.

Standalone use from F:/data: python crop_h5_ablation.py
The output keeps per-trace order and concatenates Lwk (700 samples), then
Lcomp (700 samples), writing d1_ablation.h5 and d4_ablation.h5.
"""
import argparse
import json
from pathlib import Path
import h5py
import numpy as np

WINDOWS = {
    'Lwk': [[3271, 3470], [4501, 5000]],
    'Lcomp': [[6501, 6700], [7201, 7700]],
}
SLICES = [[a - 1, b] for intervals in WINDOWS.values() for a, b in intervals]


def crop_one(source_path, output_path, batch_rows=64):
    source_path, output_path = Path(source_path), Path(output_path)
    if output_path.exists():
        raise FileExistsError(f'Refusing to overwrite {output_path}.')
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(output_path.name + '.partial')
    if temporary.exists():
        raise FileExistsError(f'Remove or rename incomplete output {temporary} before retrying.')
    try:
        with h5py.File(source_path, 'r') as src, h5py.File(temporary, 'x') as dst:
            if 'traces' not in src or src['traces'].ndim != 2:
                raise ValueError(f'{source_path}: expected root-level /traces with shape (N,samples).')
            traces = src['traces']
            count, samples = traces.shape
            if samples < 7700:
                raise ValueError(f'{source_path}: need at least 7700 points, found {samples}.')
            if batch_rows < 1:
                raise ValueError('batch_rows must be positive.')
            dst.attrs.update(dict(src.attrs))
            dst.attrs.update(complete=False, num_captured=0, samples=1400,
                             original_samples=samples,
                             ablation_windows=json.dumps(WINDOWS, separators=(',', ':')),
                             ablation_layout='Lwk first (700 samples), followed by Lcomp (700 samples); intervals 1-based inclusive',
                             ablation_source=str(source_path.resolve()))
            out = dst.create_dataset('traces', (count, 1400), dtype=traces.dtype,
                                     chunks=(1, 1400))
            for name, value in traces.attrs.items():
                out.attrs[name] = value
            for begin in range(0, count, batch_rows):
                end = min(count, begin + batch_rows)
                # Read each original trace chunk once, then select the four windows.
                source_block = traces[begin:end, :7700]
                blocks = [source_block[:, first:last] for first, last in SLICES]
                block = np.concatenate(blocks, axis=1)
                if block.shape != (end - begin, 1400):
                    raise ValueError('Internal crop length mismatch.')
                out[begin:end] = block
                dst.attrs.modify('num_captured', end)
                if begin == 0 or end == count or end // 1000 != begin // 1000:
                    print(f'{source_path.name}: {end}/{count} traces cropped', flush=True)
            for name, obj in src.items():
                if name == 'traces':
                    continue
                if isinstance(obj, h5py.Dataset):
                    src.copy(obj, dst, name=name)
                else:
                    src.copy(obj, dst, name=name)
            if not bool(src.attrs.get('complete', True)):
                raise ValueError(f'{source_path}: source is marked incomplete.')
            # Verify a representative row directly against the source intervals.
            for row in sorted(set([0, count // 2, count - 1])):
                expected = np.concatenate([traces[row, first:last] for first, last in SLICES])
                np.testing.assert_array_equal(out[row], expected)
            dst.attrs.modify('complete', True)
        temporary.rename(output_path)
    except Exception:
        # Keep a partial H5 for inspection; its complete attribute remains false.
        raise
    print(f'Validated {output_path} (shape: {count} x 1400)', flush=True)
    return output_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent,
                        help='Folder containing d1.h5 and d4.h5; default is this script folder.')
    parser.add_argument('--batch-rows', type=int, default=64)
    parser.add_argument('--overwrite', action='store_true',
                        help='Replace only the two named ablation outputs from a previous crop.')
    args = parser.parse_args()
    root = args.root.resolve()
    inputs = [root / 'd1.h5', root / 'd4.h5']
    outputs = [root / 'd1_ablation.h5', root / 'd4_ablation.h5']
    for path in inputs:
        if not path.is_file():
            raise FileNotFoundError(path)
    generated = outputs + [p.with_name(p.name + '.partial') for p in outputs]
    for path in generated:
        if path.exists():
            if not args.overwrite:
                raise FileExistsError(f'{path} exists. Pass --overwrite to recrop these named outputs.')
            path.unlink()
    for source, output in zip(inputs, outputs):
        crop_one(source, output, args.batch_rows)


if __name__ == '__main__':
    main()
