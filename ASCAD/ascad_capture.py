#!/usr/bin/env python3
"""Capture CW303 Boolean masked AES experiments, using fresh OS randomness.

Dependencies: chipwhisperer, numpy, h5py, pycryptodome.
This records ADC waveforms, not calibrated energy in joules.
"""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import secrets
import time

import h5py
import numpy as np
from Crypto.Cipher import AES

RANDOM_BYTES = 34
IDENTITY = bytes([0xAC, 1, 1, RANDOM_BYTES])
DEFAULT_KEY = "0d0e0f00090a0b0c0506070801020304"


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def aes_block(value):
    try:
        block = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected hexadecimal bytes") from exc
    if len(block) != 16:
        raise argparse.ArgumentTypeError("expected exactly 16 bytes (32 hex digits)")
    return block


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--waves", type=positive_int, default=10)
    parser.add_argument("--samples", type=positive_int, default=15000)
    parser.add_argument("--offset", type=int, default=0, help="ADC clocks after trigger")
    parser.add_argument("--decimate", type=positive_int, default=1)
    parser.add_argument("--key", type=aes_block, default=aes_block(DEFAULT_KEY))
    parser.add_argument("--random-key", action="store_true", help="fresh AES key per trace")
    parser.add_argument("--plaintext", type=aes_block, help="fixed plaintext; default: random")
    parser.add_argument("--output", type=Path, default=Path("ascad_capture/trace.h5"))
    parser.add_argument("--firmware", type=Path,
                        default=Path(__file__).with_name("ascad_capture-CW303.hex"))
    parser.add_argument("--no-program", action="store_true", help="use already flashed firmware")
    parser.add_argument("--timeout-ms", type=positive_int, default=10000)
    parser.add_argument("--progress-every", type=positive_int, default=50)
    parser.add_argument("--require-full-trace", action="store_true",
                        help="reject a window that does not cover the entire trigger")
    args = parser.parse_args(argv)
    if args.offset < 0:
        parser.error("--offset must be nonnegative")
    if args.require_full_trace and args.offset:
        parser.error("--require-full-trace requires --offset 0")
    if args.output.exists():
        parser.error(f"output already exists: {args.output}; choose a new file")
    if not args.no_program and not args.firmware.is_file():
        parser.error(f"firmware missing: {args.firmware}; build Makefile.ascad_capture first")
    return args


def wait_ack(target, timeout_ms):
    status = target.simpleserial_wait_ack(timeout=timeout_ms)
    if status is None:
        raise RuntimeError("Missing SimpleSerial acknowledgement; capture stopped")
    if status != 0:
        raise RuntimeError(f"Firmware status {status}: 1=length, 2=no key, 3=no fresh masks")


def command(target, cmd, data, timeout_ms):
    target.simpleserial_write(cmd, bytearray(data))
    wait_ack(target, timeout_ms)


def response(target, length, timeout_ms):
    data = target.simpleserial_read("r", length, timeout=timeout_ms, ack=False)
    if data is None or len(data) != length:
        raise RuntimeError(f"Missing/invalid {length}-byte response; capture stopped")
    wait_ack(target, timeout_ms)
    return bytes(data)


def capture_one(scope, target, key, plaintext, timeout_ms):
    # Always set the key, including fixed-key runs: k invalidates any old masks.
    command(target, "k", key, timeout_ms)
    masks = secrets.token_bytes(RANDOM_BYTES)
    command(target, "m", masks, timeout_ms)
    scope.arm()
    target.simpleserial_write("p", bytearray(plaintext))
    timed_out = scope.capture()
    ciphertext = response(target, 16, timeout_ms)
    if timed_out:
        raise RuntimeError("Scope capture timed out; this trace was not saved")
    if ciphertext != AES.new(key, AES.MODE_ECB).encrypt(plaintext):
        raise RuntimeError("AES ciphertext mismatch; this trace was not saved")
    trace = np.asarray(scope.get_last_trace(), dtype=np.float32)
    if trace.shape != (int(scope.adc.samples),) or not np.all(np.isfinite(trace)):
        raise RuntimeError("Invalid ADC trace length/data; this trace was not saved")
    trigger_cycles = int(scope.adc.trig_count)
    return trace, ciphertext, masks, trigger_cycles


def create_datasets(file, samples, waves):
    datasets = {}
    for name, width, dtype in (("traces", samples, np.float32),
                               ("plaintext", 16, np.uint8),
                               ("ciphertext", 16, np.uint8),
                               ("key", 16, np.uint8),
                               ("masks", RANDOM_BYTES, np.uint8)):
        datasets[name] = file.create_dataset(name, shape=(0, width),
                                            maxshape=(waves, width), dtype=dtype,
                                            chunks=(1, width))
    for name, dtype in (("trigger_cycles", np.uint64), ("full_window", np.bool_)):
        datasets[name] = file.create_dataset(name, shape=(0,), maxshape=(waves,),
                                            dtype=dtype, chunks=True)
    return datasets


def append_record(file, datasets, values):
    # num_captured is a commit marker: only rows below it are valid after a crash.
    row = int(file.attrs["num_captured"])
    for name, dataset in datasets.items():
        dataset.resize(row + 1, axis=0)
        dataset[row] = values[name]
    file.attrs.modify("num_captured", row + 1)


def run(args, cw):
    scope = None
    target = None
    try:
        scope = cw.scope()
        scope.default_setup()
        scope.adc.samples = args.samples
        scope.adc.offset = args.offset
        scope.adc.decimate = args.decimate
        scope.adc.presamples = 0
        scope.adc.basic_mode = "rising_edge"
        scope.adc.timeout = args.timeout_ms / 1000.0
        scope.trigger.triggers = "tio4"
        target = cw.target(scope, cw.targets.SimpleSerial)
        if not args.no_program:
            cw.program_target(scope, cw.programmers.XMEGAProgrammer, str(args.firmware))
        time.sleep(1)
        target.flush()
        target.simpleserial_write("i", bytearray())
        if response(target, 4, args.timeout_ms) != IDENTITY:
            raise RuntimeError("Wrong firmware/core revision; flash ascad_capture-CW303.hex")
        command(target, "x", b"", args.timeout_ms)

        # Known-answer capture verifies both protocol and trigger before creating a file.
        known_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        known_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        _, ct, _, cycles = capture_one(scope, target, known_key, known_pt, args.timeout_ms)
        if ct.hex() != "69c4e0d86a7b0430d8cdb78070b4c55a":
            raise RuntimeError("FIPS-197 known-answer test failed")
        window = int(scope.adc.samples) * int(scope.adc.decimate)
        full = args.offset == 0 and 0 < cycles <= window
        print(f"Sanity check passed; trigger={cycles} ADC clocks; window={window} ADC clocks")
        if not full:
            message = ("The window does not cover the entire trigger (or its duration is unavailable). "
                       "Increase --samples/--decimate for full coverage; larger decimation loses detail.")
            if args.require_full_trace:
                raise RuntimeError(message)
            print("NOTE: " + message)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with h5py.File(args.output, "x") as file:
            file.attrs.update({
                "implementation": "Boolean masked C experiment v1; NOT original ASCAD",
                "random_source": "secrets.token_bytes / OS CSPRNG; not a board TRNG",
                "mask_layout": "state[0:16], sbox_input[16], sbox_output[17], key[18:34]",
                "trigger_region": "post-sharing AES core: initial AddRoundKey, ten rounds, final state unmask; excludes masked key expansion, S-box table preparation, and plaintext sharing",
                "trace_units": "ChipWhisperer normalized ADC amplitude; not joules",
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "requested_traces": args.waves, "num_captured": 0, "complete": False,
                "samples": int(scope.adc.samples), "offset": int(scope.adc.offset),
                "decimate": int(scope.adc.decimate), "adc_freq_hz": float(scope.clock.adc_freq),
                "clkgen_freq_hz": float(scope.clock.clkgen_freq),
                "key_mode": "random" if args.random_key else "fixed",
                "plaintext_mode": "fixed" if args.plaintext is not None else "random",
                "scope_settings": str(scope), "chipwhisperer_version": str(cw.__version__),
                "firmware_path": str(args.firmware.resolve()), "programmed": not args.no_program,
            })
            datasets = create_datasets(file, int(scope.adc.samples), args.waves)
            start = time.monotonic()
            try:
                for i in range(args.waves):
                    key = secrets.token_bytes(16) if args.random_key else args.key
                    plaintext = args.plaintext if args.plaintext is not None else secrets.token_bytes(16)
                    trace, ciphertext, masks, cycles = capture_one(scope, target, key, plaintext,
                                                                   args.timeout_ms)
                    full = args.offset == 0 and 0 < cycles <= window
                    if args.require_full_trace and not full:
                        raise RuntimeError("Trace window no longer covers the entire trigger")
                    values = {"traces": trace, "trigger_cycles": cycles, "full_window": full}
                    for name, value in (("plaintext", plaintext), ("ciphertext", ciphertext),
                                        ("key", key), ("masks", masks)):
                        values[name] = np.frombuffer(value, dtype=np.uint8)
                    append_record(file, datasets, values)
                    if (i+1) % args.progress_every == 0 or i+1 == args.waves:
                        file.flush()
                        elapsed = time.monotonic() - start
                        remaining = elapsed / (i+1) * (args.waves-i-1)
                        print(f"{i+1}/{args.waves}  elapsed={elapsed:.1f}s  remaining={remaining:.1f}s")
                file.attrs.modify("complete", True)
            except BaseException as exc:
                file.attrs["error"] = f"{type(exc).__name__}: {exc}"
                raise
            finally:
                # Discard any partially appended row following a handled write error.
                committed = int(file.attrs["num_captured"])
                for dataset in datasets.values():
                    dataset.resize(committed, axis=0)
                file.flush()
        print(f"Saved {args.waves} verified traces to {args.output.resolve()}")
    finally:
        try:
            if target is not None:
                target.dis()
        finally:
            if scope is not None:
                scope.dis()


def main():
    args = arguments()
    import chipwhisperer as cw
    run(args, cw)


if __name__ == "__main__":
    main()
