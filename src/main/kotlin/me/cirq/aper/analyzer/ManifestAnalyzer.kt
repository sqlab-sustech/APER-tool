package me.cirq.aper.analyzer

import me.cirq.aper.Config
import me.cirq.aper.entity.APermission
import me.cirq.aper.entity.JClass
import me.cirq.aper.util.FileUtil
import net.dongliu.apk.parser.ApkFile
import net.dongliu.apk.parser.bean.ApkMeta
import org.w3c.dom.Document
import org.w3c.dom.Element
import org.xml.sax.InputSource
import java.io.IOException
import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.xpath.XPathConstants
import javax.xml.xpath.XPathFactory


object ManifestAnalyzer {

    private val manifest: ApkMeta by lazy {
        val apkFile = Config.get().apkFile.toFile()
        ApkFile(apkFile).apkMeta
    }

    private val manifestXml: Document by lazy {
        val apkFile = ApkFile(Config.get().apkFile.toFile())
        val xmlReader = StringReader(apkFile.manifestXml)
        val xmlInput = InputSource(xmlReader)
        val dBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
        dBuilder.parse(xmlInput)
    }

    val manifestText: String by lazy {
        val apkFile = ApkFile(Config.get().apkFile.toFile())
        apkFile.manifestXml
    }

    val permissions: Set<String>
        get() = manifest.usesPermissions.toSet()

    val packageName: String
        get() = manifest.packageName

    val targetSdkVersion: Int
        get() = manifest.targetSdkVersion?.toInt()?:-1

    val minSdkVersion: Int
        get() = manifest.minSdkVersion?.toInt()?:-1

    val applicationClass: JClass? by lazy {
        val xPath = XPathFactory.newInstance().newXPath()
        val xpath = "/manifest/application"
        val application = xPath.evaluate(xpath, manifestXml, XPathConstants.NODE) as Element
        val name = application.getAttribute("android:name")
        if(name == "") null else JClass(name)
    }

    val mainActivityClass: JClass? by lazy {
        val xPath = XPathFactory.newInstance().newXPath()
        val xpath = "/manifest/application/activity[intent-filter/action/@*[name()='android:name']='android.intent.action.MAIN']"
        val activity = xPath.evaluate(xpath, manifestXml, XPathConstants.NODE) as Element
        val name = activity.getAttribute("android:name")
        if(name == "") null else JClass(name)
    }


    private var apkPermissions: Set<APermission>? = null
    private var apkDangerousPermissions: Set<APermission>? = null

    fun getApkPermissions(save:Boolean): Set<APermission> {
        if(apkPermissions == null) {
            apkPermissions = permissions.map{ APermission(it) }.toHashSet()
        }

        if(save) {
            FileUtil.writeSetTo(apkPermissions, "AppDeclaredPermissions.txt");
        }
        return apkPermissions!!
    }

    fun getApkDangerousPermissions(save:Boolean): Set<APermission> {
        if(apkDangerousPermissions == null) {
            val allDangerous: MutableSet<APermission> = mutableSetOf()
            try {
                val filePath = Config.get().versionDangerousFile.toString()
                val lines = FileUtil.readLinesFrom(filePath);
                allDangerous.addAll(lines.map{ APermission(it) })
            } catch (ex: IOException) {}
            apkDangerousPermissions = getApkPermissions(false).filter{ allDangerous.contains(it) }.toHashSet()
        }

        if(save) {
            FileUtil.writeSetTo(apkDangerousPermissions, "AppDeclaredDangerousPermissions.txt");
        }
        return apkDangerousPermissions!!
    }

}
