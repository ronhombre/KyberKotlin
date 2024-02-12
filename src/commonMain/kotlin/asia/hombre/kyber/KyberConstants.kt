/*
 * Copyright 2024 Ron Lauren Hombre
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

package asia.hombre.kyber

import kotlin.jvm.JvmField

/**
 * Constants for ML-KEM.
 *
 * This class contains precomputed values for optimization purposes.
 *
 * @author Ron Lauren Hombre
 */
class KyberConstants {
    companion object {
        /**
         * Number of polynomials.
         */
        const val N: Int = 256

        /**
         * The byte size of the number of polynomials in bits.
         */
        const val N_BYTES: Int = N shr 3

        /**
         * Prime Integer composed of (2^8 * 13) + 1.
         */
        const val Q: Int = 3329

        /**
         * Negated modular inverse of Q base 2^16
         */
        const val Q_INV: Int = -62209 //Generated using KyberMath.powMod(Q, -1, 2^16) and negated

        /**
         * Half of Q rounded to the closest whole integer.
         */
        const val Q_HALF: Int = 1665 //round(Q/2)

        /**
         * Approximation of Q for Barrett Reduction
         */
        const val BARRETT_APPROX: Short = 20159 //(((1L shl 26) + (Q / 2)) / Q).toShort()
        //const val MONT_R: Int = 1 shl 16
        /**
         * 2^16 * 2^16 mod Q for Montgomery Reduction.
         */
        const val MONT_R2: Short = 1353 //MONT_R.toLong() shl 16 <- mod Q = 1353 //Basically R^2 mod Q

        /**
         * The length of the Secret Key in bytes.
         */
        const val SECRET_KEY_LENGTH: Int = N_BYTES

        /**
         * Encoding size for encoding coefficients and terms.
         */
        const val ENCODE_SIZE: Int = 3 * N shr 1 //Sums up to 384

        /**
         * Pre-generated Zeta values according to the formula 17^bitReverse(n) mod Q and converted to Montgomery Form.
         */
        @JvmField
        val PRECOMPUTED_ZETAS_TABLE = shortArrayOf(
            1, 2571, 2970, 1812, 1493, 1422, 287, 202,
            3158, 622, 1577, 182, 962, 2127, 1855, 1468,
            573, 2004, 264, 383, 2500, 1458, 1727, 3199,
            2648, 1017, 732, 608, 1787, 411, 3124, 1758,
            1223, 652, 2777, 1015, 2036, 1491, 3047, 1785,
            516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
            2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
            2931, 961, 1821, 2604, 448, 2264, 677, 2054,
            2226, 430, 555, 843, 2078, 871, 1550, 105,
            422, 587, 177, 3094, 3038, 2869, 1574, 1653,
            3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
            1739, 644, 2457, 349, 418, 329, 3173, 3254,
            817, 1097, 603, 610, 1322, 2044, 1864, 384,
            2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
            2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
            3221, 3021, 996, 991, 958, 1869, 1522, 1628
            /*1, 1729, 2580, 3289, 2642, 630, 1897, 848,
            1062, 1919, 193, 797, 2786, 3260, 569, 1746,
            296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
            1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
            289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
            650, 1977, 2513, 632, 2865, 33, 1320, 1915,
            2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
            2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
            17, 2761, 583, 2649, 1637, 723, 2288, 1100,
            1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
            1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
            939, 2308, 2437, 2388, 733, 2337, 268, 641,
            1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
            1063, 319, 2773, 757, 2099, 561, 2466, 2594,
            2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
            1722, 1212, 1874, 1029, 2110, 2935, 885, 2154*/
        ) //Generated using Generators.generateZetas() test method

        /**
         * Pre-generated Zeta values according to the formula 17^(2 * bitReverse(n)) mod Q and converted to Montgomery Form.
         */
        @JvmField
        val PRECOMPUTED_GAMMAS_TABLE = shortArrayOf(
            2226, 1103, 430, 2899, 555, 2774, 843, 2486,
            2078, 1251, 871, 2458, 1550, 1779, 105, 3224,
            422, 2907, 587, 2742, 177, 3152, 3094, 235,
            3038, 291, 2869, 460, 1574, 1755, 1653, 1676,
            3083, 246, 778, 2551, 1159, 2170, 3182, 147,
            2552, 777, 1483, 1846, 2727, 602, 1119, 2210,
            1739, 1590, 644, 2685, 2457, 872, 349, 2980,
            418, 2911, 329, 3000, 3173, 156, 3254, 75,
            817, 2512, 1097, 2232, 603, 2726, 610, 2719,
            1322, 2007, 2044, 1285, 1864, 1465, 384, 2945,
            2114, 1215, 3193, 136, 1218, 2111, 1994, 1335,
            2455, 874, 220, 3109, 2142, 1187, 1670, 1659,
            2144, 1185, 1799, 1530, 2051, 1278, 794, 2535,
            1819, 1510, 2475, 854, 2459, 870, 478, 2851,
            3221, 108, 3021, 308, 996, 2333, 991, 2338,
            958, 2371, 1869, 1460, 1522, 1807, 1628, 1701
            /*17, 3312, 2761, 568, 583, 2746, 2649, 680,
            1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
            1409, 1920, 2662, 667, 3281, 48, 233, 3096,
            756, 2573, 2156, 1173, 3015, 314, 3050, 279,
            1703, 1626, 1651, 1678, 2789, 540, 1789, 1540,
            1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
            939, 2390, 2308, 1021, 2437, 892, 2388, 941,
            733, 2596, 2337, 992, 268, 3061, 641, 2688,
            1584, 1745, 2298, 1031, 2037, 1292, 3220, 109,
            375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
            1063, 2266, 319, 3010, 2773, 556, 757, 2572,
            2099, 1230, 561, 2768, 2466, 863, 2594, 735,
            2804, 525, 1092, 2237, 403, 2926, 1026, 2303,
            1143, 2186, 2150, 1179, 2775, 554, 886, 2443,
            1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
            2110, 1219, 2935, 394, 885, 2444, 2154, 1175*/
        ) //Generated using Generators.generateGammas() test method
    }
}