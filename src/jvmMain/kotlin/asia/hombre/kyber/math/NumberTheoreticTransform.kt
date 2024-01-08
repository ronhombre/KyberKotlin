//Copyright 2023 Ron Lauren Hombre
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//       and included as LICENSE.txt in this Project.
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
package asia.hombre.kyber.math

internal class NumberTheoreticTransform {
    companion object {
        val ZETAS = shortArrayOf(
            2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
            2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
            732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
            1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
            107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
            430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
            1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
            418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
            1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
            478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628
        )

        val ZETAS_INV = shortArrayOf(
            1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
            1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
            1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
            1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
            3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
            1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
            1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
            2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
            829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
            3127, 3042, 1907, 1836, 1517, 359, 758, 1441
        )

        fun ntt(r: ShortArray): ShortArray {
            var j = 0
            var k = 1
            var l = 128
            while (l >= 2) {
                var start = 0
                while (start < 256) {
                    val zeta: Short = ZETAS[k]
                    k += 1
                    j = start
                    while (j < start + l) {
                        val t: Short = modQMulMont(zeta, r[j + l])
                        r[j + l] = (r[j] - t).toShort()
                        r[j] = (r[j] + t).toShort()
                        j++
                    }
                    start = j + l
                }
                l = l shr 1
            }
            return r
        }

        fun invNTT(r: ShortArray): ShortArray {
            var j = 0
            var k = 0
            var l = 2
            while (l <= 128) {
                var start = 0
                while (start < 256) {
                    val zeta: Short = ZETAS_INV[k]
                    k += 1
                    j = start
                    while (j < start + l) {
                        val t = r[j]
                        r[j] = ByteOperations.barrettReduce((t + r[j + l]).toShort())
                        r[j + l] = (t - r[j + l]).toShort()
                        r[j + l] = modQMulMont(zeta, r[j + l])
                        j++
                    }
                    start = j + l
                }
                l = l shl 1
            }
            j = 0
            while (j < 256) {
                r[j] = modQMulMont(r[j], ZETAS_INV[127])
                j++
            }
            return r
        }

        fun baseMultiplier(a0: Short, a1: Short, b0: Short, b1: Short, zeta: Short): ShortArray {
            val r = ShortArray(2)
            r[0] = modQMulMont(a1, b1)
            r[0] = modQMulMont(r[0], zeta)
            r[0] = (r[0] + modQMulMont(a0, b0)).toShort()
            r[1] = modQMulMont(a0, b1)
            r[1] = (r[1] + modQMulMont(a1, b0)).toShort()
            return r
        }

        private fun modQMulMont(a: Short, b: Short): Short {
            return ByteOperations.montgomeryReduce((a.toLong() * b.toLong()))
        }
    }
}