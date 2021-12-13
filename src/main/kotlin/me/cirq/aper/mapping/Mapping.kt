package me.cirq.aper.mapping

import me.cirq.aper.Config
import me.cirq.aper.entity.APermission
import me.cirq.aper.entity.JMethod
import me.cirq.aper.util.FileUtil
import me.cirq.aper.util.LogUtil
import java.io.IOException
import java.nio.file.Path


interface Mapping {

    companion object {
        fun get(mapping: String, mappingDir: Path, tv: Int): Mapping {
            LogUtil.info(this, "Getting {} mapping for SDK-version {}", mapping, tv)
            return when(mapping.lowercase()) {
                "pscout" -> PscoutMapping(mappingDir.resolve("API_$tv"))
                "axplorer" -> AxplorerMapping(mappingDir.resolve("api-$tv"))
                "aper" -> ArpMapping(mappingDir.resolve("API$tv"))
                else -> throw IllegalArgumentException("invalid mapping: $mapping")
            }
        }
        fun getArpMethodMapOf(tv: Int): ArpMethodMapMap {
            return ArpMethodMapMap.create(tv)
        }
    }

    fun mapPermissionToMethods(): Map<APermission,Set<JMethod>>

}

class ArpMethodMapMap private constructor(_tv: Int): HashMap<JMethod,Set<APermission>>() {
    private val mapping = ArpMapping(Config.get().mappingDir.resolve("API$_tv"))
    init {
        mapping.mapPermissionToMethods().forEach{ (p, ms) ->
            for(method in ms) {
                if(method !in this)
                    this[method] = hashSetOf(p)
                else
                    this[method] = this[method]!!.toMutableSet().also{ it.add(p) }
            }
        }
    }
    companion object {
        private val store = HashMap<Int,ArpMethodMapMap>()
        fun create(tv: Int): ArpMethodMapMap {
            if(tv in store)
                return store[tv]!!
            LogUtil.debug(this, "Building ARP mapping for SDK-version {}", tv)
            val newMap = ArpMethodMapMap(tv)
            store[tv] = newMap
            return newMap
        }
    }
}


internal class ArpMapping(private val mappingDir: Path): Mapping {
    init {
        if(!mappingDir.toFile().isDirectory)
            throw IOException("no such dir: $mappingDir")
    }

    override fun mapPermissionToMethods(): Map<APermission,Set<JMethod>> {
        val map: MutableMap<APermission, MutableSet<JMethod>> = HashMap()
        for(file in mappingDir.toFile().listFiles()!!) {
            if(!file.name.endsWith("-Mappings.txt"))
                continue
            FileUtil.readLinesFrom(file.absolutePath).forEach{ line ->
                val parts = line.split(" :: ")
                val sig = parts[0]
                val method = if('<' in sig)
                    JMethod.fromAxplorerSignature(sig.replace("""<.+?>""".toRegex(), ""))
                else
                    JMethod.fromAxplorerSignature(sig)

                if(method.methodName == "getExternalStorageDirectory") {
                    if(!Config.get().withExdir) {
                        LogUtil.debug(this, "skip getExternalStorageDirectory")
                        return@forEach  // to reduce false positives
                    }
                }

                val perms = parts[1].split(", ")
                if(parts.size == 3) {
                    // parts[2] is either allOf or anyOf
                    PermissionCombination.put(method, parts[2])
                }
                perms.filter{ it.startsWith("android.permission.") }.forEach{
                    val permission = APermission(it)
                    if(permission !in map)
                        map[permission] = HashSet()
                    map[permission]!! += method
                }
            }
        }
        map.keys.retainAll(PscoutMapping.dangerousPermissions)
        return map
    }
}


internal class AxplorerMapping(private val mappingDir: Path): Mapping {
    init {
        if(!mappingDir.toFile().isDirectory)
            throw IOException("no such dir: $mappingDir")
    }

    override fun mapPermissionToMethods(): Map<APermission,Set<JMethod>> {
        val map: MutableMap<APermission, MutableSet<JMethod>> = HashMap()
        for(file in mappingDir.toFile().listFiles()!!) {
            if(file.name.startsWith("cp-map-")) // unhandle content provider
                continue
            FileUtil.readLinesFrom(file.absolutePath).forEach{ line ->
                val parts = line.split("  ::  ")
                val perms = parts[1].split(", ")
                perms.filter{ it.startsWith("android.permission.") }.forEach{ perm ->
                    val permission = APermission(perm)
                    if(permission !in map)
                        map[permission] = HashSet()
                    map[permission]!! += JMethod.fromAxplorerSignature(parts[0])
                }
            }
        }
        map.keys.retainAll(PscoutMapping.dangerousPermissions)
        return map
    }
}


internal class PscoutMapping(private val mappingDir: Path): Mapping {
    init {
        if(!mappingDir.toFile().exists())
            throw IOException("no such dir: $mappingDir")
    }

    companion object {
        val dangerousPermissions: Set<APermission> by lazy {
            val filePath = Config.get().versionDangerousFile.toString()
            FileUtil.readLinesFrom(filePath)
                    .map { APermission(it) }
                    .toSet()
        }
    }

    // not test
    override fun mapPermissionToMethods(): Map<APermission, Set<JMethod>> {
        val permissionToApi: MutableMap<APermission, MutableSet<JMethod>> = HashMap()
        val mappingFiles = arrayOf("publishedapimapping", "allmappings")
        for (mappingFile in mappingFiles) {
            val filePath = mappingDir.resolve(mappingFile).toString()
            var tempPermission: APermission? = null
            val lines = FileUtil.readLinesFrom(filePath)
            for (st in lines) {
                if (st.contains("Permission:") || st.contains("PERMISSION:")) {
                    tempPermission = APermission(st.split(":".toRegex()).toTypedArray()[1])
                    if (permissionToApi.containsKey(tempPermission)) {
                        continue
                    }
                    permissionToApi[tempPermission] = HashSet()
                } else if (!st.contains("Callers:")) {
                    val substring = st.substring(st.indexOf("<"), st.lastIndexOf(">")+1)
                    val method = JMethod.fromSootSignature(substring)
                    permissionToApi[tempPermission]!! += method
                }
            }
        }
        permissionToApi.keys.retainAll(dangerousPermissions)
        return permissionToApi
    }
}
