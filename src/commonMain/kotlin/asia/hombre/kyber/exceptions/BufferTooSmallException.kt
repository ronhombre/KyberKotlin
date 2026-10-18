package asia.hombre.kyber.exceptions

/** An output buffer cannot hold the requested ML-KEM result. */
class BufferTooSmallException : IllegalArgumentException("The output buffer is too small.")
