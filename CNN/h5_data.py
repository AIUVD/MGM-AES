"""Bounded-memory readers for custom captures and optional official ASCAD files."""
from pathlib import Path
import h5py
import numpy as np
from tensorflow import keras
from aes import AES_Sbox


def byte_array(value, name, ndim):
    a = np.asarray(value)
    if (a.ndim != ndim or not np.issubdtype(a.dtype, np.integer) or
            np.any(a < 0) or np.any(a > 255)):
        raise ValueError(f'{name} must be a {ndim}-D integer array in [0, 255].')
    return a.astype(np.uint8)


class H5Source:
    def __init__(self, config, role):
        official = config['data_format'] == 'ascad'
        self.path = config['data'] if official else config['train_h5' if role == 'profile' else 'attack_h5']
        self.group = ('Profiling_traces' if role == 'profile' else 'Attack_traces') if official else '/'
        self.count = config['profile_num' if role == 'profile' else 'attack_pool']
        self.start = config['trace_start']
        self.byte = config['byte']
        with h5py.File(self.path, 'r') as f:
            g = f[self.group]
            traces = g['traces']
            if traces.ndim != 2:
                raise ValueError('traces must have shape (number_of_traces, samples).')
            self.length = config['trace_length'] or (traces.shape[1] - self.start)
            if traces.shape[0] < self.count or self.length < 2 or self.start + self.length > traces.shape[1]:
                raise ValueError(f'{self.path}: traces {traces.shape}; need at least ({self.count}, {self.start + self.length}).')
            if 'complete' in f.attrs and not bool(f.attrs['complete']):
                raise ValueError(f'{self.path}: capture marked incomplete.')
            if official:
                md = g['metadata']
                if len(md) < self.count or 'plaintext' not in (md.dtype.names or ()):
                    raise ValueError('metadata must contain plaintext for each trace.')
                self.plaintext = byte_array(md[:self.count]['plaintext'], 'plaintext', 2)
                keys = byte_array(md[:self.count]['key'], 'key', 2) if 'key' in md.dtype.names else None
            else:
                self.plaintext = byte_array(g['plaintext'][:self.count], 'plaintext', 2)
                keys = byte_array(g['key'][:self.count], 'key', 2) if 'key' in g else None
            if len(self.plaintext) != self.count or not 0 <= self.byte < self.plaintext.shape[1]:
                raise ValueError('plaintext shape must be (N, bytes); check target byte and HDF5 orientation.')
            specified = config['key']
            if keys is not None:
                if len(keys) != self.count or self.byte >= keys.shape[1]:
                    raise ValueError('key shape must be (N, bytes).')
                selected_keys = keys[:, self.byte]
                if specified is not None and np.any(selected_keys != specified):
                    raise ValueError('--key conflicts with this file key values; omit it to read /key.')
            elif specified is not None:
                selected_keys = np.full(self.count, specified, dtype=np.uint8)
            else:
                raise ValueError('Missing /key: explicitly provide --key for captures without stored keys.')
            if role == 'attack' and np.any(selected_keys != selected_keys[0]):
                raise ValueError('Repeated rank attacks require a fixed target key byte in the attack set.')
            self.key = int(selected_keys[0])
            self.labels = AES_Sbox[np.bitwise_xor(self.plaintext[:, self.byte], selected_keys)].astype(np.uint8)
            if 'labels' in g:
                provided = byte_array(g['labels'][:self.count], 'labels', 1)
                if not np.array_equal(provided, self.labels):
                    raise ValueError('labels must equal Sbox[plaintext[:, byte] XOR key_byte].')
            elif official:
                raise ValueError('Official ASCAD groups must contain labels.')
            self.report = dict(path=str(Path(self.path)), role=role, traces_shape=list(traces.shape),
                               selected_rows=self.count, trace_start=self.start, trace_length=self.length,
                               target_byte=self.byte, first_target_key=self.key,
                               unique_target_keys=int(np.unique(selected_keys).size))
            for attr in ['complete', 'num_captured', 'samples', 'adc_freq_hz', 'clkgen_freq_hz', 'key_mode']:
                if attr in f.attrs:
                    value = f.attrs[attr]
                    self.report[attr] = value.item() if isinstance(value, np.generic) else value
            if 'full_window' in g:
                flags = g['full_window'][:self.count]
                self.report['full_window_false_count'] = int(np.count_nonzero(~flags.astype(bool)))
            if 'trigger_cycles' in g:
                cycles = g['trigger_cycles'][:self.count]
                self.report['trigger_cycles_min'] = int(cycles.min())
                self.report['trigger_cycles_max'] = int(cycles.max())

    def read(self, indices):
        """Read a slice or unique row indices, preserving the requested order."""
        with h5py.File(self.path, 'r') as f:
            traces = f[self.group]['traces']
            window = slice(self.start, self.start + self.length)
            if isinstance(indices, slice):
                x = traces[indices, window]
            else:
                indices = np.asarray(indices)
                order = np.argsort(indices)
                x = traces[indices[order], window][np.argsort(order)]
        x = np.asarray(x, dtype=np.float32)
        if not np.isfinite(x).all():
            raise ValueError(f'{self.path}: traces contain NaN or infinity.')
        return x


def fit_streaming(source, method, chunk_size=256):
    if method == 'none':
        return dict(method=np.array(method))
    # Merge chunk means/M2 rather than allocating a full float64 trace array.
    count = 0
    mean = np.zeros(source.length, dtype=np.float64)
    m2 = np.zeros_like(mean)
    minimum = np.full(source.length, np.inf)
    maximum = np.full(source.length, -np.inf)
    for begin in range(0, source.count, chunk_size):
        x = source.read(slice(begin, min(source.count, begin + chunk_size))).astype(np.float64)
        n = len(x)
        local_mean = x.mean(axis=0)
        delta = local_mean - mean
        m2 += ((x - local_mean)**2).sum(axis=0) + delta**2 * count * n / (count + n)
        mean += delta * n / (count + n)
        count += n
        minimum = np.minimum(minimum, x.min(axis=0))
        maximum = np.maximum(maximum, x.max(axis=0))
    std = np.sqrt(np.maximum(m2 / count, 0))
    std[std < 1e-12] = 1
    stats = dict(method=np.array(method), mean=mean, std=std)
    if method == 'standard-minmax':
        low = (minimum - mean) / std
        span = (maximum - minimum) / std
        span[span < 1e-12] = 1
        stats.update(low=low, span=span)
    return stats


def transform(x, stats):
    method = str(stats['method'])
    if method == 'none':
        return np.asarray(x, dtype=np.float32)
    x = (x - stats['mean']) / stats['std']
    if method == 'standard-minmax':
        x = (x - stats['low']) / stats['span']
    return np.asarray(x, dtype=np.float32)


class TraceBatches(keras.utils.PyDataset):
    def __init__(self, source, indices, stats, batch_size, shuffle=False, seed=0):
        super().__init__(workers=1, use_multiprocessing=False, max_queue_size=2)
        self.source, self.stats, self.batch_size = source, stats, batch_size
        self.indices = np.asarray(indices).copy()
        self.shuffle = shuffle
        self.rng = np.random.default_rng(seed)

    def __len__(self):
        return (len(self.indices) + self.batch_size - 1) // self.batch_size

    def __getitem__(self, index):
        rows = self.indices[index * self.batch_size:(index + 1) * self.batch_size]
        x = transform(self.source.read(rows), self.stats)[..., None]
        y = keras.utils.to_categorical(self.source.labels[rows], 256)
        return x, y

    def on_epoch_end(self):
        if self.shuffle:
            self.rng.shuffle(self.indices)
