'use strict';

const _queueAsyncBuckets = new Map();

/**
 * Adiciona uma tarefa a uma fila específica, garantindo execução serial.
 * @param {any} bucket - Identificador único da fila.
 * @param {Function} awaitable - Função assíncrona a ser executada.
 * @returns {Promise} Promessa resolvida ou rejeitada após a execução do job.
 */
module.exports = function (bucket, awaitable) {
    if (!_queueAsyncBuckets.has(bucket)) {
        _queueAsyncBuckets.set(bucket, { queue: [], active: false });
    }

    const bucketQueue = _queueAsyncBuckets.get(bucket);

    const job = new Promise((resolve, reject) => {
        bucketQueue.queue.push({ awaitable, resolve, reject });
    });

    if (!bucketQueue.active) {
        bucketQueue.active = true;
        _processQueue(bucket, bucketQueue);
    }

    return job;
};

/**
 * Processa a fila de um bucket de forma serial.
 * @param {any} bucket - Identificador único do bucket.
 * @param {Object} bucketQueue - Estrutura da fila do bucket.
 */
async function _processQueue(bucket, bucketQueue) {
    while (bucketQueue.queue.length > 0) {
        const { awaitable, resolve, reject } = bucketQueue.queue.shift();
        try {
            const result = await awaitable();
            resolve(result);
        } catch (err) {
            reject(err);
        }
    }

    bucketQueue.active = false;
    if (bucketQueue.queue.length === 0) {
        _queueAsyncBuckets.delete(bucket);
    }
}
