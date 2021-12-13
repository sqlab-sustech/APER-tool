package me.cirq.aper.util

import java.io.Serializable


// https://stackoverflow.com/a/54609291
data class Quadruple<out A,out B,out C,out D>(val first: A,
                                              val second: B,
                                              val third: C,
                                              val fourth: D): Serializable {
    override fun toString(): String = "($first, $second, $third, $fourth)"
}
fun <T> Quadruple<T, T, T, T>.toList(): List<T> = listOf(first, second, third, fourth)

data class Quintuple<out A,out B,out C,out D,out E>(val first: A,
                                                    val second: B,
                                                    val third: C,
                                                    val fourth: D,
                                                    val fifth: E): Serializable {
    override fun toString(): String = "($first, $second, $third, $fourth, $fifth)"
}
fun <T> Quintuple<T, T, T, T, T>.toList(): List<T> = listOf(first, second, third, fourth, fifth)


fun <T> List<T>.last(n: Int): T {
    return this[this.size-n]
}

fun <T> Collection<T>?.nothing(): Boolean {
    return this==null || this.isEmpty()
}

fun <T> Collection<T>?.notvoid(): Boolean {
    return this!=null && this.isNotEmpty()
}

fun <T> Iterator<T>.toList(): List<T> {
    return this.asSequence().toList()
}

fun <T> Iterator<T>.filterToList(block: (T)->Boolean): List<T> {
    return this.toList().filter(block)
}

fun <T> Iterator<T>.uniqueToList(block: (T)->Boolean): List<T> {
    return this.toList().filter(block).distinct()
}
