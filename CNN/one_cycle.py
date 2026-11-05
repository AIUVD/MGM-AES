"""Adam one-cycle policy compatible with current tf.keras.

Same three linear phases as the author's callback: 40% up, 40% down,
20% final decay. Momentum is not cycled for Adam.
"""
import numpy as np
from tensorflow import keras


class OneCycleLR(keras.callbacks.Callback):
    def __init__(self, max_lr, total_steps):
        super().__init__()
        if max_lr <= 0 or total_steps < 3:
            raise ValueError('One-cycle needs max_lr > 0 and at least 3 training batches.')
        self.max_lr = float(max_lr)
        self.total_steps = int(total_steps)
        self.mid = max(1, int(total_steps * 0.4))
        self.rates = []

    def rate_at(self, step):
        low = self.max_lr * 0.1
        if step <= self.mid:
            return low + (self.max_lr - low) * step / self.mid
        if step <= 2 * self.mid:
            return self.max_lr - (self.max_lr - low) * (step - self.mid) / self.mid
        return low * (1 - 0.99 * (step - 2 * self.mid) /
                      (self.total_steps - 2 * self.mid))

    def on_train_begin(self, logs=None):
        self.rates = []
        self.model.optimizer.learning_rate.assign(self.rate_at(0))

    def on_train_batch_end(self, batch, logs=None):
        self.rates.append(float(np.asarray(self.model.optimizer.learning_rate)))
        self.model.optimizer.learning_rate.assign(self.rate_at(len(self.rates)))
