package me.cirq.aper.analyzer.step

import me.cirq.aper.analyzer.ManifestAnalyzer
import me.cirq.aper.entity.APermission
import me.cirq.aper.util.FileUtil


/* The Step 1 */
object DeclareStep {

    fun isPermissionDeclared(permissions: Set<APermission>): Map<APermission,Boolean> {
        val declaredPermissions = ManifestAnalyzer.getApkDangerousPermissions(false)
        return permissions.map{
            it to (it in declaredPermissions) }.toMap()
    }

    fun saveDeclaredPermissions(filename: String) {
        val allPerm = ManifestAnalyzer.getApkPermissions(false)
        val allDangPerm = ManifestAnalyzer.getApkDangerousPermissions(false)
        val lines = allPerm.map{
            if(it in allDangPerm) "$it [DANGEROUS]" else it.toString() }.toList()
        FileUtil.writeListTo(lines, filename)
    }

}