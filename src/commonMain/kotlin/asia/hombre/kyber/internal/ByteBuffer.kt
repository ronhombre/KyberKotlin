/*
 * Copyright 2026 Ron Lauren Hombre
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *        
 *        and included as LICENSE.txt in this Project.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
