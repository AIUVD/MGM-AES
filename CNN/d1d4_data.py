"""Disjoint analysis windows and metadata for the d1 -> d4 experiment."""
import h5py
import numpy as np
from h5_data import H5Source as BaseSource, byte_array

DEFAULT_SAMPLE_RANGES = '3271:3420,4581:4780,6521:6620,7401:7650'


def parse_sample_ranges(text):
    """1-based inclusive user ranges -> zero-based half-open intervals."""
    result = []
    try:
        for part in text.split(','):
            first, last = map(int, part.split(':'))
            if first < 1 or last < first or (result and first <= result[-1][1]):
                raise ValueError()
            result.append([first - 1, last])
    except (TypeError, ValueError):
        raise ValueError('Use ordered, non-overlapping 1-based ranges such as 3271:3420,4581:4780.') from None
    if not result:
        raise ValueError('At least one sample range is required.')
    return result


class H5Source(BaseSource):
    def __init__(self, config, role):
        if config['byte'] != 0:
            raise ValueError('This d1/d4 experiment targets the first byte only (--byte 0).')
        self.ranges = config['sample_ranges']
        base = dict(config, trace_start=0, trace_length=max(end for _, end in self.ranges))
        super().__init__(base, role)
        if self.report['unique_target_keys'] != 1:
            raise ValueError('d1/d4 experiment requires a fixed first key byte in each file.')
        with h5py.File(self.path, 'r') as f:
            g = f[self.group]
            if 'rk' not in g:
                raise ValueError(f'{self.path}: missing /rk. Use convert_txt_to_h5.py.')
            rk = byte_array(g['rk'][:self.count], 'rk', 2)
            if rk.shape != (self.count, 16) or np.any(rk[:, 0] != rk[0, 0]):
                raise ValueError('Expected /rk with shape (N,16) and a fixed first byte.')
            expected_group = 1 if role == 'profile' else 4
            if 'key_group' in f.attrs and int(f.attrs['key_group']) != expected_group:
                raise ValueError(f'{role} must use group {expected_group}; check d1/d4 paths.')
            self.rk = int(rk[0, 0])
        self.start = self.ranges[0][0]
        self.length = sum(end - begin for begin, end in self.ranges)
        self.sample_indices = np.concatenate([np.arange(begin, end) for begin, end in self.ranges])
        self.report.update(trace_start=self.start, trace_length=self.length,
                           sample_ranges_one_based=[[a + 1, b] for a, b in self.ranges],
                           sample_index_convention='ordered concatenation; ranges are 1-based inclusive',
                           first_rk_byte=self.rk)

    def read(self, indices):
        with h5py.File(self.path, 'r') as f:
            traces = f[self.group]['traces']
            if isinstance(indices, slice):
                blocks = [traces[indices, start:end] for start, end in self.ranges]
            else:
                indices = np.asarray(indices)
                order = np.argsort(indices)
                inverse = np.argsort(order)
                blocks = [traces[indices[order], start:end][inverse] for start, end in self.ranges]
        x = np.concatenate(blocks, axis=1).astype(np.float32, copy=False)
        if not np.isfinite(x).all():
            raise ValueError(f'{self.path}: selected samples contain NaN/Inf.')
        return x


def prepare_targets(config, profile=None, attack=None):
    if profile is not None:
        config['profiling_reference'] = dict(k1=profile.key, rk1=profile.rk)
    if attack is None:
        return
    reference = config.get('profiling_reference')
    if reference is None:
        raise ValueError('Saved model lacks the d1 profiling key/rk reference.')
    k1, rk1 = reference['k1'], reference['rk1']
    k4, rk4 = attack.key, attack.rk
    config['target_spec'] = dict(
        names=['k4', 'k1', 'k1^rk1', 'k4^rk4', 'k4^rk1^rk4'],
        values=[k4, k1, k1 ^ rk1, k4 ^ rk4, k4 ^ rk1 ^ rk4],
        focus_index=4, k1=k1, rk1=rk1, k4=k4, rk4=rk4,
        label_rule='Sbox[plaintext[:,0] XOR key[:,0]]',
        focus_is_physical_key=False)
