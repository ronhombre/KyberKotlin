package asia.hombre.kyber

import asia.hombre.kyber.internal.SecureRandom
import kotlin.math.roundToInt
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.time.measureTime

@Ignore
class Benchmark {

    @Test
    fun secureRandom() {
        println("Secure Random Benchmark...")

        var averageRatio = 50.0;

        val benchmark = measureTime {
            for(i in 0..<100) {
                val bytes = SecureRandom.generateSecureBytes(32)
                var positive = 0
                var negative = 0
                for(b in bytes) {
                    if(b > 0xb)
                        positive++
                    else
                        negative++
                }
                val ratio = ((positive.toDouble() / (positive + negative).toDouble()) * 1000).roundToInt() / 10.0
                //println("P: $positive | N: $negative | R: $ratio | " + bytes.joinToString(", "))
                averageRatio = (averageRatio + ratio) / 2.0
            }
        }

        println("Average Ratio: $averageRatio")
        println("Time Elapsed: " + benchmark.inWholeMilliseconds)
    }
}