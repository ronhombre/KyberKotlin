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

class KyberConstants {
    companion object {
        const val N: Int = 256
        const val N_BYTES: Int = N shr 3
        const val Q: Int = 3329
        const val Q_INV: Int = 62209 //Generated using KyberMath.powMod(Q, -1, 2^16)
        const val SECRET_KEY_LENGTH = N_BYTES

        val PRECOMPUTED_ZETAS_TABLE = shortArrayOf(
            1, 1729, 2580, 3289, 2642, 630, 1897, 848,
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
            1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
        ) //Generated using Generators.generateZetas() test method

        val PRECOMPUTED_GAMMAS_TABLE = shortArrayOf(
            17, 3312, 2761, 568, 583, 2746, 2649, 680,
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
            2110, 1219, 2935, 394, 885, 2444, 2154, 1175
        ) //Generated using Generators.generateGammas() test method
    }
}