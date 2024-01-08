package asia.hombre.kyber

enum class KyberParameter(val K: Int, val ETA1: Int, val ETA2: Int, val DU: Int, val DV: Int) {
    ML_KEM_512(2, 3, 2, 10, 4),
    ML_KEM_768(3, 2, 2, 10, 4),
    ML_KEM_1024(4, 2, 2, 11, 5)
}