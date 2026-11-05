"""Create F:/data/d3_ablation.h5 from the d3 hexadecimal capture."""
from pathlib import Path
import h5py
import numpy as np
from aes import AES_Sbox

ROOT = Path(r'F:\data')
FOLDER = ROOT / 'd3'
OUT = ROOT / 'd3_ablation.h5'
PART = ROOT / 'd3_ablation.h5.partial'
KEY = np.array([0x00,0x01,0x20,0x01,0x71,0x01,0x98,0xae,0xda,0x79,0x17,0x14,0x60,0x15,0x35,0x94], dtype=np.uint8)
RK = np.array([0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f], dtype=np.uint8)
SLICES = [(3270,3470),(4500,5000),(6500,6700),(7200,7700)]
BATCH = 64

def read_plain(path):
    a = np.loadtxt(path, dtype='U2', ndmin=2)
    if a.shape[1] != 16:
        raise ValueError(f'Expected 16 plaintext bytes per row, got {a.shape}')
    return np.asarray([[int(v,16) for v in row] for row in a], dtype=np.uint8)

def main():
    if OUT.exists() or PART.exists():
        raise FileExistsError(f'Refusing to overwrite {OUT} or {PART}')
    plain = read_plain(FOLDER/'plain.txt')
    n = len(plain)
    if plain.shape[1] != 16:
        raise ValueError('Invalid plaintext shape')
    wave = FOLDER/'wave.txt'
    anchors = {}
    print(f'Converting {n} d3 traces into {OUT}', flush=True)
    with h5py.File(PART, 'x') as f, wave.open('rb') as src:
        f.attrs.update(complete=False, num_captured=0, samples=1400,
                       original_samples=10000, dataset_name='d3', key_mode='fixed',
                       source_folder=str(FOLDER), source_wave=str(wave),
                       ablation_windows='Lwk: 3271-3470,4501-5000; Lcomp: 6501-6700,7201-7700 (1-based inclusive)',
                       ablation_layout='Lwk first (700 samples), Lcomp second (700 samples)')
        traces=f.create_dataset('traces',(n,1400),dtype='i4',chunks=(16,1400),compression='gzip',compression_opts=1,shuffle=True)
        f.create_dataset('plaintext',data=plain,dtype='u1')
        f.create_dataset('key',data=np.broadcast_to(KEY,(n,16)),dtype='u1',chunks=(1024,16))
        f.create_dataset('rk',data=np.broadcast_to(RK,(n,16)),dtype='u1',chunks=(1024,16))
        f.create_dataset('trace_index',data=np.arange(n,dtype='u8'))
        f.create_dataset('labels',data=AES_Sbox[np.bitwise_xor(plain[:,0],KEY[0])],dtype='u1')
        for begin in range(0,n,BATCH):
            end=min(n,begin+BATCH)
            block=np.empty((end-begin,1400),dtype=np.int32)
            for row in range(begin,end):
                line=src.readline()
                if not line: raise ValueError(f'{wave}: ended at trace {row}')
                values=np.fromiter((int(v,16) for v in line.split()),dtype=np.int32)
                if len(values)<7700: raise ValueError(f'{wave}: trace {row} has only {len(values)} samples')
                block[row-begin]=np.concatenate([values[a:b] for a,b in SLICES])
                if row in (0,n//2,n-1): anchors[row]=block[row-begin].copy()
            traces[begin:end]=block
            f.attrs.modify('num_captured',end)
            if begin==0 or end==n or end//10000!=begin//10000: print(f'{end}/{n}',flush=True)
        for row, expected in anchors.items(): np.testing.assert_array_equal(traces[row],expected)
        f.attrs.modify('complete',True)
    PART.replace(OUT)
    print(f'Validated {OUT}: {n} x 1400',flush=True)

if __name__=='__main__': main()
