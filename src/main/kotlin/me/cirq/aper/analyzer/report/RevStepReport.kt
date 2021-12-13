package me.cirq.aper.analyzer.report

import me.cirq.aper.entity.*
import me.cirq.aper.util.FileUtil
import java.nio.file.Path
import java.nio.file.Paths


class RevStepReport {
    lateinit var checkMap: Map<JMethod,Set<PCallChain>>
    lateinit var requestMap: Map<JMethod,Set<PCallChain>>

    private var _storePaths: MutableMap<JMethod,Path> = HashMap()
    val storePaths: Map<JMethod,Path> get() = _storePaths

    fun addCheckResult(result: Set<PCallChain>): DumpableResult<PCallChain> {
        val map: MutableMap<JMethod,MutableSet<PCallChain>> = HashMap()
        result.forEach{
            if(it.api !in map)
                map[it.api] = HashSet()
            map[it.api]!!.add(it)
        }
        checkMap = map
        return DumpableResult(map, "check")
    }

    fun addRequestResult(result: Set<PCallChain>): DumpableResult<PCallChain> {
        val map: MutableMap<JMethod,MutableSet<PCallChain>> = HashMap()
        result.forEach{
            if(it.api !in map)
                map[it.api] = HashSet()
            map[it.api]!!.add(it)
        }
        requestMap = map
        return DumpableResult(map, "request")
    }

    inner class DumpableResult<T:ACallChain>(val map: Map<JMethod,Set<T>>, private val prefix: String) {
        fun dump(): Iterator<String> = iterator {
            map.forEach { (api, chain) ->
                val content = chain.joinToString("\n\n---\n\n") { toMethodsList(it) }
                val fileName = "$prefix-$api.txt"
                val path = Paths.get("revreports", fileName)
                _storePaths[api] = path
                FileUtil.writeStringTo(content, path.toString())
                yield(fileName)
            }
        }
        private fun toMethodsList(chain: ACallChain): String {
            val permStr = when(chain) {
                is DCallChain -> ""
                is PCallChain -> chain.permissions.joinToString(",")
            }
            val mtdStr = chain.withIndex()
                              .joinToString("\n") { (i, method) -> "  ".repeat(i)+method }
            return "[$permStr]\n$mtdStr"
        }
    }

}
