package me.cirq.aper.analyzer.report

import me.cirq.aper.Config
import me.cirq.aper.analyzer.step.CheckSite
import me.cirq.aper.analyzer.step.RequestSite
import me.cirq.aper.entity.APermission
import me.cirq.aper.entity.DCallChain
import me.cirq.aper.util.FileUtil
import soot.SootMethod
import soot.toolkits.graph.Block
import java.nio.file.Path
import java.util.*


class StepReport(_chain: DCallChain) {
    private val count = ++counter

    val api = _chain.api
    val chain = _chain.chain
    val permissionReports = _chain.permissions
                                  .map{ it to PermissionReport() }
                                  .toMap()

    lateinit var storePath: Path

    companion object {
        private var counter = 0
    }

    class PermissionReport {
        val _isDeclared: Array<Boolean> = arrayOf(false)
        val isDeclared: Boolean get() = _isDeclared[0]

        val _checkSites: MutableList<CheckSite> = LinkedList()
        val checkSites: List<CheckSite> get() = _checkSites

        val _requestSites: MutableList<RequestSite> = LinkedList()
        val requestSites: List<RequestSite> get() = _requestSites

        val _handleCallbacks: MutableList<SootMethod> = LinkedList()
        val handleCallbacks: List<SootMethod> get() = _handleCallbacks

        fun toReportString(indent: Int): String {
            val sindent = "\t".repeat(indent)
            val sb = StringBuilder()

            val step1 = "${sindent}Is Declared: ${_isDeclared[0]}\n"
            sb.append(step1)

            val s2body = toMethodsList(_checkSites.map{ it.second }, sindent, 13)
            val step2 = "${sindent}Check Sites: $s2body\n"
            sb.append(step2)

            val s3body = toMethodsList(_requestSites.map{ it.second }, sindent, 15)
            val step3 = "${sindent}Request Sites: $s3body\n"
            sb.append(step3)

            val s4body = toMethodsList(_handleCallbacks, sindent, 12)
            val step4 = String.format("${sindent}Has Handle: $s4body\n", sindent, s4body)
            sb.append(step4)

            return sb.toString()
        }

        private fun toBlocksList(blocks: List<Block>, indent: String, align: Int): String {

            fun toBlockString(b: Block) = "in ${b.body.method.signature}"

            return if(blocks.isEmpty())
                "NONE"
            else {
                val sb = StringBuilder()
                blocks.withIndex().forEach{ (i, block) ->
                    if(i > 0)
                        sb.append("\n$indent${" ".repeat(align)}")
                    sb.append(toBlockString(block))
                }
                sb.toString()
            }
        }

        private fun toMethodsList(methods: List<SootMethod>, indent: String, align: Int): String {

            fun toMethodString(m: SootMethod) = "in ${m.signature}"

            return if(methods.isEmpty()) {
                "NONE"
            }
            else {
                val sb = StringBuilder()
                methods.withIndex().forEach{ (i, method) ->
                    if(i > 0)
                        sb.append("\n$indent${" ".repeat(align)}")
                    sb.append(toMethodString(method))
                }
                sb.toString()
            }
        }
    }


    fun addDeclareResult(result: Map<APermission,Boolean>) {
        result.forEach { (k, v) -> permissionReports.getValue(k)._isDeclared[0] = v }
    }

    fun addCheckResult(result: Map<APermission,List<CheckSite>>) {
        result.forEach { (k, v) -> permissionReports.getValue(k)._checkSites.addAll(v) }
    }

    fun addRequestResult(result: Map<APermission,List<RequestSite>>) {
        result.forEach { (k, v) -> permissionReports.getValue(k)._requestSites.addAll(v) }
    }

    fun addHandleResult(result: Map<APermission,List<SootMethod>>) {
        result.forEach { (k, v) -> permissionReports.getValue(k)._handleCallbacks.addAll(v) }
    }

    private fun toHeaderApi() = "API:\n\t${api.sootSignature}"

    private fun toHeaderPermissions() = "PERMISSIONS:\n\t[${permissionReports.keys.joinToString(",")}]"

    private fun toHeaderCallchain() = "CALLCHAIN:" + chain.withIndex().joinToString("") {
                                                        (i, c) -> "\n\t${" ".repeat(i)}${c}" }

    fun dump(): String {
        val hApi = toHeaderApi()
        val hPermissions = toHeaderPermissions()
        val hCallchain = toHeaderCallchain()
        val header = listOf(hApi, hPermissions, hCallchain).joinToString("\n---\n")
        val body = permissionReports.map { (p, r) -> "DANGEROUS: $p\n${r.toReportString(1)}" }
                                           .joinToString("\n---\n")
        val content = "$header\n\n======\n\n$body"
        val fileName = "${count.format()}-$api.txt".replace("[<>]".toRegex(), "")
        val output = Config.get().apkOutputDir
        storePath = output.resolve("reports").resolve(fileName).toAbsolutePath()
        FileUtil.writeStringTo(content, storePath.toString())
        return fileName
    }

    private fun Int.format(length: Int=3) = "%0${length}d".format(this)
}
