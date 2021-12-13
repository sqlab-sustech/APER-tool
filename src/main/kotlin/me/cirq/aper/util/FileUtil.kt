package me.cirq.aper.util;

import me.cirq.aper.Config;
import me.cirq.aper.entity.APermission;
import me.cirq.aper.entity.DCallChain;
import me.cirq.aper.entity.JMethod;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.*


object FileUtil {

    private const val ENCODING: String  = "UTF-8"

    @JvmStatic
    fun readLinesFrom(filePath: String): List<String> {
        val file = File(filePath);
        return FileUtils.readLines(file, ENCODING)
    }

    @JvmStatic
    fun writeSetTo(set: Set<Any>?, filePath: String) {
        writeCollection(set, filePath)
    }

    @JvmStatic
    fun writeListTo(list: List<Any>, filePath: String) {
        writeCollection(list, filePath)
    }

    @JvmStatic
    fun writeMethodMapTo(map: Map<JMethod,Set<APermission>>, filePath: String) {
        val strings: MutableList<Any> = LinkedList()
        map.forEach { (method, permissions) ->
            strings.add("Method:$method")
            strings.addAll(permissions)
            strings.add("")
        }
        writeCollection(strings, filePath)
    }

    @JvmStatic
    fun writeCallchainsTo(chains: Set<DCallChain>, filePath: String) {
        val strings: MutableList<Any> = LinkedList()
        chains.forEach {
            val chain = it.chain
            val permissions = it.permissions
            val sb = StringBuilder(permissions.toString())
            sb.append("\n${chain[0]}\n")
            for(i in 1 until chain.size) {
                val lead = String.format("%${i}c", ' ')
                sb.append(lead)
                sb.append("${chain[i]}\n")
            }
            strings.add(sb.toString())
        }
        writeCollection(strings, filePath)
    }

    @JvmStatic
    fun writeStringTo(string: String, filePath: String) {
        writeContent(string, filePath)
    }

    @JvmStatic
    fun appendStringTo(string: String, filePath: String) {
        appendContent(string, filePath)
    }



    private fun writeCollection(collection: Collection<Any>?, filePath: String) {
        val realPath = Config.get().apkOutputDir.resolve(filePath)
        val file = realPath.toFile()

        try {
            FileUtils.writeLines(file, ENCODING, collection, false)
        } catch (ex: IOException) {
            ex.printStackTrace()
        }
    }

    private fun writeContent(content: String, filePath: String) {
        val realPath = Config.get().apkOutputDir.resolve(filePath)
        val file = realPath.toFile()

        try {
            FileUtils.writeStringToFile(file, content, ENCODING, false)
        } catch (ex: IOException) {
            ex.printStackTrace()
        }
    }

    private fun appendContent(content: String, filePath: String) {
        val realPath = Config.get().apkOutputDir.resolve(filePath)
        val file = realPath.toFile()

        try {
            FileUtils.writeStringToFile(file, content, ENCODING, true)
        } catch (ex: IOException) {
            ex.printStackTrace()
        }
    }

}
