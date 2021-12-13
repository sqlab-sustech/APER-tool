package me.cirq.aper.tag

import soot.tagkit.Tag


class RvAvailable private constructor(val rv: Int): Tag {
    companion object {
        private val cache = HashMap<Int,RvAvailable>()
        fun tag(rv: Int): RvAvailable {
            if(rv !in cache)
                cache[rv] = RvAvailable(rv)
            return cache[rv]!!
        }
    }

    override fun getName() = "tag.rvavail.$rv"

    override fun getValue() = name.toByteArray()
}
