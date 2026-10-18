package asia.hombre.kyber.internal

internal class ByteBuffer(val array: ByteArray, val offset: Int = 0, val size: Int = array.size - offset) {
    init {
        require(offset >= 0 && size >= 0 && offset <= array.size - size)
    }

    operator fun get(index: Int): Byte {
        require(index in 0 until size)
        return array[offset + index]
    }

    fun slice(start: Int, end: Int = size): ByteBuffer {
        require(start in 0..end && end <= size)
        return ByteBuffer(array, offset + start, end - start)
    }

    fun copyOf(): ByteArray = array.copyOfRange(offset, offset + size)

    fun copyInto(destination: ByteArray, destinationOffset: Int = 0) {
        array.copyInto(destination, destinationOffset, offset, offset + size)
    }

    fun contentEquals(other: ByteBuffer): Boolean =
        size == other.size && (0 until size).all { this[it] == other[it] }

    fun contentHashCode(): Int {
        var result = 1
        for (element in this.array) result = 31 * result + element
        return result
    }
}
